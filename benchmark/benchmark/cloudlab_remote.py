# Copyright(C) Facebook, Inc. and its affiliates.
"""
CloudLab Remote Benchmark

This module provides functionality to run benchmarks on CloudLab nodes.
"""

from collections import OrderedDict
from pathlib import Path
from fabric import Connection, ThreadingGroup as Group
from fabric.exceptions import GroupException
from paramiko import RSAKey
from paramiko.ssh_exception import PasswordRequiredException, SSHException
from time import sleep
from math import ceil
from copy import deepcopy
import subprocess
import re
import shlex
import ipaddress

from benchmark.config import Committee, Key, NodeParameters, BenchParameters, ConfigError
from benchmark.utils import BenchError, Print, PathMaker
from benchmark.commands import CommandMaker
from benchmark.logs import LogParser, ParseError
from benchmark.cloudlab_instance import CloudLabInstanceManager
from benchmark.imbalanced_rate import ZipfAllocator


def _fabric_connection_label(conn) -> str:
    """Best-effort hostname for a Fabric Connection (GroupResult dict key)."""
    return str(getattr(conn, "host", conn))


def _print_fabric_group_diagnostics(group_result, title: str) -> None:
    """
    Print stdout/stderr for every host in a Fabric GroupResult.

    Used when Group.run(..., hide=True) fails so cargo/git errors are visible.
    Values may be invoke Result objects or BaseException if the runner failed.
    """
    Print.info(title)
    for conn, value in group_result.items():
        label = _fabric_connection_label(conn)
        if isinstance(value, BaseException):
            Print.info(f"  --- {label}: runner error {type(value).__name__}: {value} ---")
            continue
        ok = getattr(value, "ok", None)
        exited = getattr(value, "exited", None)
        Print.info(f"  --- {label} (ok={ok}, exited={exited}) ---")
        stdout = (getattr(value, "stdout", None) or "").rstrip()
        stderr = (getattr(value, "stderr", None) or "").rstrip()
        if stdout:
            Print.info("  [stdout]\n" + stdout)
        if stderr:
            Print.info("  [stderr]\n" + stderr)
        if not stdout and not stderr:
            Print.info("  (no stdout/stderr captured)")


class FabricError(Exception):
    """Wrapper for Fabric exception with a meaningful error message."""

    def __init__(self, error):
        assert isinstance(error, GroupException)
        parts = []
        for conn, value in error.result.items():
            label = _fabric_connection_label(conn)
            if isinstance(value, BaseException):
                parts.append(f"{label}: {type(value).__name__}: {value}")
                continue
            if getattr(value, "ok", True):
                continue
            tail = (getattr(value, "stderr", None) or "").strip()
            if not tail:
                tail = (getattr(value, "stdout", None) or "").strip()
            if len(tail) > 2000:
                tail = "... " + tail[-2000:]
            parts.append(f"{label}: exit={getattr(value, 'exited', '?')} {tail}")
        message = "\n".join(parts) if parts else str(list(error.result.values())[-1])
        super().__init__(message)


class ExecutionError(Exception):
    pass


class CloudLabBench:
    """Benchmark runner for CloudLab nodes"""
    
    def __init__(self, ctx):
        self.manager = CloudLabInstanceManager.make()
        self.settings = self.manager.settings
        
        try:
            # Try to load key without password first
            try:
                ctx.connect_kwargs.pkey = RSAKey.from_private_key_file(
                    self.manager.settings.key_path
                )
            except PasswordRequiredException:
                # Key is password-protected, try to get password
                import os
                password = os.environ.get('SSH_KEY_PASSWORD')
                
                # Try to get password from cloudlab_settings.json if it exists
                if not password:
                    try:
                        import json
                        settings_file = Path(__file__).parent.parent / 'cloudlab_settings.json'
                        if settings_file.exists():
                            with open(settings_file, 'r') as f:
                                settings_data = json.load(f)
                                password = settings_data.get('ssh_key_password')
                    except Exception:
                        pass
                
                if password:
                    ctx.connect_kwargs.pkey = RSAKey.from_private_key_file(
                        self.manager.settings.key_path,
                        password=password
                    )
                else:
                    raise BenchError(
                        'SSH key is password-protected. Please provide password via SSH_KEY_PASSWORD environment variable or ssh_key_password in cloudlab_settings.json',
                        PasswordRequiredException('private key file is encrypted')
                    )
            self.connect = ctx.connect_kwargs
        except (IOError, PasswordRequiredException, SSHException) as e:
            raise BenchError('Failed to load SSH key', e)
    
    def _check_stderr(self, output):
        if isinstance(output, dict):
            for x in output.values():
                if x.stderr:
                    raise ExecutionError(x.stderr)
        else:
            if output.stderr:
                raise ExecutionError(output.stderr)
    
    def _get_connection_kwargs(self, host_info):
        """Get connection kwargs for a specific host (without port/timeout, passed separately)"""
        # Create a new dict from connect_kwargs (which is a Config object)
        # Don't include port or timeout here - they will be passed as separate parameters
        kwargs = dict(self.connect)
        # Remove port and timeout if they exist to avoid ambiguity
        kwargs.pop('port', None)
        kwargs.pop('timeout', None)
        kwargs.pop('connect_timeout', None)
        return kwargs

    @staticmethod
    def _normalize_ipv4(value, label='Host'):
        """Validate and normalize an IPv4 address stored in settings."""
        host = value.split(':')[0]
        try:
            address = ipaddress.ip_address(host)
        except ValueError as e:
            raise BenchError(f'{label} "{value}" is not a valid IPv4 address', e)

        if address.version != 4:
            raise BenchError(f'{label} "{value}" must be an IPv4 address')

        return str(address)

    def _discover_interconnect_subnets(self, hosts, prefix):
        """Derive routed subnets from the configured CloudLab hosts."""
        assert isinstance(hosts, list)

        if prefix < 1 or prefix > 32:
            raise BenchError(f'Invalid IPv4 prefix length: {prefix}')

        subnets = []
        seen = set()

        for host in hosts:
            host_ip = self._normalize_ipv4(host['hostname'])
            network = ipaddress.ip_network(f'{host_ip}/{prefix}', strict=False)
            network_str = str(network)
            if network_str not in seen:
                seen.add(network_str)
                subnets.append(network_str)

        return subnets

    @staticmethod
    def _build_interconnect_command(
        remote_script,
        action,
        role,
        gateway,
        subnets=None,
        verify_hosts=None,
        local_ip=None,
        dev=None,
    ):
        """Build a safely quoted remote command line for the interconnect script."""
        argv = [
            'bash',
            remote_script,
            action,
            '--role',
            role,
            '--gateway',
            gateway,
        ]

        if local_ip:
            argv += ['--local-ip', local_ip]
        if dev:
            argv += ['--dev', dev]
        if subnets:
            argv += ['--subnets', ','.join(subnets)]
        if verify_hosts:
            argv += ['--verify-hosts', ','.join(verify_hosts)]

        return ' '.join(shlex.quote(x) for x in argv)

    def _run_interconnect_script(
        self,
        host,
        script_path,
        action,
        role,
        gateway,
        subnets=None,
        verify_hosts=None,
        local_ip=None,
        dev=None,
    ):
        """Upload and execute the interconnect helper script on a host."""
        username = host.get('username', 'root')
        hostname = host['hostname']
        port = host.get('port', 22)
        conn_kwargs = self._get_connection_kwargs(host)
        remote_script = f'/tmp/narwhal-interconnect-{role}.sh'

        conn = Connection(
            hostname,
            user=username,
            port=port,
            connect_kwargs=conn_kwargs,
            connect_timeout=30,
        )

        try:
            conn.put(str(script_path), remote=remote_script)
            command = self._build_interconnect_command(
                remote_script,
                action,
                role,
                gateway,
                subnets=subnets,
                verify_hosts=verify_hosts,
                local_ip=local_ip,
                dev=dev,
            )
            result = conn.run(
                f'chmod +x {shlex.quote(remote_script)} && {command}',
                hide=True,
                warn=True,
            )
            if not result.ok:
                stderr = result.stderr.strip()
                stdout = result.stdout.strip()
                raise ExecutionError(stderr or stdout or 'interconnect script failed')
            return result.stdout.strip()
        finally:
            try:
                conn.run(f'rm -f {shlex.quote(remote_script)}', hide=True, warn=True)
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass

    def configure_interconnect(
        self,
        gateway='10.4.1.1',
        prefix=16,
        configure_router=False,
        router_host=None,
        router_user=None,
        router_port=22,
        verify=True,
        dev=None,
        router_dev=None,
    ):
        """Configure static routes so hosts can reach each other through a gateway."""
        gateway_ip = self._normalize_ipv4(gateway, label='Gateway')
        hosts = self.manager.get_host_info()
        if not hosts:
            raise BenchError('No CloudLab hosts found in settings')

        leaf_hosts = []
        for host in hosts:
            if self._normalize_ipv4(host['hostname']) == gateway_ip:
                Print.info(f'Skipping gateway host {host["hostname"]} when applying leaf routes')
                continue
            leaf_hosts.append(host)

        if not leaf_hosts:
            raise BenchError('No non-gateway CloudLab hosts available for interconnect setup')

        script_path = (
            Path(__file__).resolve().parents[2]
            / 'script'
            / 'remote_control'
            / 'ensure_interconnect_via_gateway.sh'
        )
        if not script_path.exists():
            raise BenchError('Missing interconnect helper script', FileNotFoundError(script_path))

        subnets = self._discover_interconnect_subnets(leaf_hosts, int(prefix))
        verify_hosts = [
            self._normalize_ipv4(host['hostname']) for host in leaf_hosts
        ] if verify else None

        Print.heading(f'Configuring routed interconnect via {gateway_ip}...')
        Print.info(f'Routed networks: {", ".join(subnets)}')

        failures = []

        if configure_router:
            router_target = router_host or gateway_ip
            router_config = {
                'hostname': router_target,
                'username': router_user or leaf_hosts[0].get('username', 'root'),
                'port': int(router_port),
            }
            Print.info(
                f'Configuring router forwarding on '
                f'{router_config["username"]}@{router_config["hostname"]}:{router_config["port"]}...'
            )
            try:
                output = self._run_interconnect_script(
                    router_config,
                    script_path,
                    action='apply',
                    role='router',
                    gateway=gateway_ip,
                    dev=router_dev,
                )
                if output:
                    print(output)
            except Exception as e:
                failures.append(
                    f'{router_config["username"]}@{router_config["hostname"]}:{router_config["port"]}: {e}'
                )

        for host in leaf_hosts:
            username = host.get('username', 'root')
            hostname = host['hostname']
            port = host.get('port', 22)
            host_ip = self._normalize_ipv4(hostname)
            Print.info(f'Applying leaf routes on {username}@{hostname}:{port}...')
            try:
                output = self._run_interconnect_script(
                    host,
                    script_path,
                    action='apply',
                    role='leaf',
                    gateway=gateway_ip,
                    local_ip=host_ip,
                    dev=dev,
                )
                if output:
                    print(output)
            except Exception as e:
                failures.append(f'{username}@{hostname}:{port}: {e}')

        if verify:
            Print.info('Verifying routed connectivity on all leaf nodes...')
            for host in leaf_hosts:
                username = host.get('username', 'root')
                hostname = host['hostname']
                port = host.get('port', 22)
                host_ip = self._normalize_ipv4(hostname)
                try:
                    output = self._run_interconnect_script(
                        host,
                        script_path,
                        action='verify',
                        role='leaf',
                        gateway=gateway_ip,
                        verify_hosts=verify_hosts,
                        local_ip=host_ip,
                        dev=dev,
                    )
                    if output:
                        print(output)
                except Exception as e:
                    failures.append(f'{username}@{hostname}:{port}: {e}')

        if failures:
            raise BenchError('Failed to configure routed interconnect', ExecutionError('\n'.join(failures)))

        Print.heading('Interconnect configuration completed')

    @staticmethod
    def _infer_wan_role(hostname):
        """Infer WAN shaping role from the configured host IP."""
        if hostname.startswith('10.1.'):
            return 'eu'
        if hostname.startswith('10.2.'):
            return 'na'
        if hostname.startswith('10.3.'):
            return 'as'
        if hostname.startswith('10.4.'):
            return 'router'
        return None

    @staticmethod
    def _build_wan_command(
        remote_script,
        action,
        role,
        gateway,
        local_ip=None,
        dev=None,
        rate=None,
    ):
        """Build a safely quoted remote command line for WAN shaping."""
        argv = [
            'bash',
            remote_script,
            action,
            '--role',
            role,
            '--gateway',
            gateway,
        ]

        if local_ip:
            argv += ['--local-ip', local_ip]
        if dev:
            argv += ['--dev', dev]
        if rate:
            argv += ['--rate', rate]

        return ' '.join(shlex.quote(x) for x in argv)

    def _run_wan_script(
        self,
        host,
        script_path,
        action,
        role,
        gateway,
        local_ip=None,
        dev=None,
        rate=None,
    ):
        """Upload and execute the WAN shaping helper script on a host."""
        username = host.get('username', 'root')
        hostname = host['hostname']
        port = host.get('port', 22)
        conn_kwargs = self._get_connection_kwargs(host)
        remote_script = f'/tmp/narwhal-wan-netem-{role}.sh'

        conn = Connection(
            hostname,
            user=username,
            port=port,
            connect_kwargs=conn_kwargs,
            connect_timeout=30,
        )

        try:
            conn.put(str(script_path), remote=remote_script)
            command = self._build_wan_command(
                remote_script,
                action,
                role,
                gateway,
                local_ip=local_ip,
                dev=dev,
                rate=rate,
            )
            result = conn.run(
                f'chmod +x {shlex.quote(remote_script)} && {command}',
                hide=True,
                warn=True,
            )
            if not result.ok:
                stderr = result.stderr.strip()
                stdout = result.stdout.strip()
                raise ExecutionError(stderr or stdout or 'WAN shaping script failed')
            return result.stdout.strip()
        finally:
            try:
                conn.run(f'rm -f {shlex.quote(remote_script)}', hide=True, warn=True)
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass

    @staticmethod
    def _wan_route_probes(role):
        """Representative destinations that should route through the WAN gateway."""
        probes = {
            'eu': ['10.2.1.1', '10.3.1.1'],
            'na': ['10.1.1.1', '10.3.1.1'],
            'as': ['10.1.1.1', '10.2.1.1'],
        }
        return probes.get(role, [])

    def _verify_wan_host_state(
        self,
        host,
        script_path,
        gateway,
        role,
        local_ip=None,
        dev=None,
        rate=None,
    ):
        """Verify that a host is using the intended routed WAN path."""
        output = self._run_wan_script(
            host,
            script_path,
            action='show',
            role=role,
            gateway=gateway,
            local_ip=local_ip,
            dev=dev,
            rate=rate,
        )

        errors = []
        detected_dev = None
        for line in output.splitlines():
            if line.startswith('dev='):
                detected_dev = line.split('=', 1)[1].strip() or None
                break
        if role == 'router':
            if 'net.ipv4.ip_forward = 1' not in output:
                errors.append('router ip_forward is not enabled')
            if 'net.ipv4.conf.all.send_redirects = 0' not in output:
                errors.append('router send_redirects is not disabled')
            if 'net.ipv4.conf.all.accept_redirects = 0' not in output:
                errors.append('router accept_redirects is not disabled')
            return errors

        if 'qdisc prio 1: root' not in output:
            errors.append('root prio qdisc is missing')
        if 'flowid 1:' not in output:
            errors.append('tc destination filters are missing')
        if 'net.ipv4.conf.all.send_redirects = 0' not in output:
            errors.append('leaf send_redirects is not disabled')
        if 'net.ipv4.conf.all.accept_redirects = 0' not in output:
            errors.append('leaf accept_redirects is not disabled')
        checked_dev = dev or detected_dev
        if checked_dev and f'net.ipv4.conf.{checked_dev}.send_redirects = 0' not in output:
            errors.append(f'leaf send_redirects is not disabled on {checked_dev}')
        if checked_dev and f'net.ipv4.conf.{checked_dev}.accept_redirects = 0' not in output:
            errors.append(f'leaf accept_redirects is not disabled on {checked_dev}')

        username = host.get('username', 'root')
        hostname = host['hostname']
        port = host.get('port', 22)
        conn_kwargs = self._get_connection_kwargs(host)
        conn = Connection(
            hostname,
            user=username,
            port=port,
            connect_kwargs=conn_kwargs,
            connect_timeout=30,
        )

        try:
            conn.run(
                'sudo ip route flush cache || sudo sysctl -w net.ipv4.route.flush=1 >/dev/null',
                hide=True,
                warn=True,
            )
            for probe in self._wan_route_probes(role):
                route = conn.run(f'ip -4 route get {shlex.quote(probe)}', hide=True, warn=True)
                route_text = (route.stdout or route.stderr or '').strip()
                if f'via {gateway}' not in route_text:
                    errors.append(
                        f'route to {probe} does not use gateway {gateway}: '
                        f'{route_text or "no route output"}'
                    )
        finally:
            try:
                conn.close()
            except Exception:
                pass

        return errors

    def _ensure_verified_wan_host(
        self,
        host,
        script_path,
        gateway,
        role,
        local_ip=None,
        dev=None,
        rate=None,
        attempts=2,
    ):
        """Verify a WAN host and retry apply if the expected state is missing."""
        attempts = max(1, int(attempts))
        last_errors = []
        username = host.get('username', 'root')
        hostname = host['hostname']
        port = host.get('port', 22)

        for attempt in range(1, attempts + 1):
            errors = self._verify_wan_host_state(
                host,
                script_path,
                gateway,
                role,
                local_ip=local_ip,
                dev=dev,
                rate=rate,
            )
            if not errors:
                return None

            last_errors = errors
            if attempt == attempts:
                break

            Print.warn(
                f'WAN verification failed on {username}@{hostname}:{port} '
                f'({"; ".join(errors)}). Reapplying...'
            )
            self._run_wan_script(
                host,
                script_path,
                action='apply',
                role=role,
                gateway=gateway,
                local_ip=local_ip,
                dev=dev,
                rate=rate,
            )

        return '; '.join(last_errors)

    def configure_wan_delay(
        self,
        action='apply',
        gateway='10.4.1.1',
        configure_router=True,
        router_host=None,
        router_user=None,
        router_port=22,
        verify=True,
        dev=None,
        router_dev=None,
        rate='100mbit',
    ):
        """Configure WAN routes and tc netem rules on CloudLab hosts."""
        action = str(action).lower()
        if action not in {'apply', 'clean', 'show'}:
            raise BenchError(
                f'Invalid WAN action: {action}',
                ValueError('action must be one of apply, clean, show'),
            )

        gateway_ip = self._normalize_ipv4(gateway, label='Gateway')
        hosts = self.manager.get_host_info()
        if not hosts:
            raise BenchError('No CloudLab hosts found in settings', ValueError('empty host list'))

        script_path = (
            Path(__file__).resolve().parents[2]
            / 'script'
            / 'remote_control'
            / 'configure_wan_netem.sh'
        )
        if not script_path.exists():
            raise BenchError('Missing WAN helper script', FileNotFoundError(script_path))

        eligible_hosts = []
        for host in hosts:
            host_ip = self._normalize_ipv4(host['hostname'])
            role = self._infer_wan_role(host_ip)
            if role in {'eu', 'na', 'as'}:
                eligible_hosts.append((host, host_ip, role))
            elif host_ip == gateway_ip and not configure_router:
                Print.info(f'Skipping gateway host {host_ip}')

        if not eligible_hosts:
            raise BenchError(
                'No WAN leaf hosts found in settings',
                ValueError('expected 10.1.x, 10.2.x, or 10.3.x hosts'),
            )

        failures = []
        Print.heading(f'Applying WAN action "{action}" via gateway {gateway_ip}...')

        if configure_router:
            router_target = router_host or gateway_ip
            router_config = {
                'hostname': router_target,
                'username': router_user or eligible_hosts[0][0].get('username', 'root'),
                'port': int(router_port),
            }
            Print.info(
                f'Configuring router on '
                f'{router_config["username"]}@{router_config["hostname"]}:{router_config["port"]}...'
            )
            try:
                output = self._run_wan_script(
                    router_config,
                    script_path,
                    action=action,
                    role='router',
                    gateway=gateway_ip,
                    local_ip=gateway_ip,
                    dev=router_dev,
                    rate=rate,
                )
                if output:
                    print(output)
            except Exception as e:
                failures.append(
                    f'{router_config["username"]}@{router_config["hostname"]}:{router_config["port"]}: {e}'
                )

        for host, host_ip, role in eligible_hosts:
            username = host.get('username', 'root')
            hostname = host['hostname']
            port = host.get('port', 22)
            Print.info(f'Configuring {role.upper()} host {username}@{hostname}:{port}...')
            try:
                output = self._run_wan_script(
                    host,
                    script_path,
                    action=action,
                    role=role,
                    gateway=gateway_ip,
                    local_ip=host_ip,
                    dev=dev,
                    rate=rate,
                )
                if output:
                    print(output)
            except Exception as e:
                failures.append(f'{username}@{hostname}:{port}: {e}')

        if verify and action == 'apply':
            Print.info('Verifying routed WAN state on all hosts...')
            if configure_router:
                router_target = router_host or gateway_ip
                router_config = {
                    'hostname': router_target,
                    'username': router_user or eligible_hosts[0][0].get('username', 'root'),
                    'port': int(router_port),
                }
                try:
                    error = self._ensure_verified_wan_host(
                        router_config,
                        script_path,
                        gateway_ip,
                        role='router',
                        local_ip=gateway_ip,
                        dev=router_dev,
                        rate=rate,
                        attempts=2,
                    )
                    if error:
                        failures.append(
                            f'{router_config["username"]}@{router_config["hostname"]}:{router_config["port"]}: {error}'
                        )
                except Exception as e:
                    failures.append(
                        f'{router_config["username"]}@{router_config["hostname"]}:{router_config["port"]}: {e}'
                    )

            for host, host_ip, role in eligible_hosts:
                username = host.get('username', 'root')
                hostname = host['hostname']
                port = host.get('port', 22)
                try:
                    error = self._ensure_verified_wan_host(
                        host,
                        script_path,
                        gateway_ip,
                        role=role,
                        local_ip=host_ip,
                        dev=dev,
                        rate=rate,
                        attempts=2,
                    )
                    if error:
                        failures.append(f'{username}@{hostname}:{port}: {error}')
                except Exception as e:
                    failures.append(f'{username}@{hostname}:{port}: {e}')

        if failures:
            raise BenchError('Failed to configure WAN delay', ExecutionError('\n'.join(failures)))

        Print.heading('WAN delay configuration completed')
    
    def test_connections(self):
        """Test SSH connections to all CloudLab nodes"""
        Print.heading('Testing connections to CloudLab nodes...')
        
        host_info = self.manager.get_host_info()
        conn_kwargs = self._get_connection_kwargs({})
        
        results = {
            'success': [],
            'failed': []
        }
        
        for host in host_info:
            username = host.get('username', 'root')
            hostname = host['hostname']
            port = host.get('port', 22)
            region = host.get('region', 'default')
            
            Print.info(f'Testing {username}@{hostname}:{port} ({region})...')
            
            try:
                # Test basic connection
                test_conn = Connection(
                    hostname, 
                    user=username, 
                    port=port, 
                    connect_kwargs=conn_kwargs, 
                    connect_timeout=10
                )
                test_conn.open()
                
                # Test basic command execution
                result = test_conn.run('echo "Connection test successful" && hostname && uname -a', hide=True)
                test_conn.close()
                
                # Parse output
                output_lines = result.stdout.strip().split('\n')
                hostname_line = output_lines[1] if len(output_lines) > 1 else "N/A"
                system_line = output_lines[-1] if len(output_lines) > 0 else result.stdout.strip()
                
                Print.info(f'  ✓ Connected successfully')
                Print.info(f'    Hostname: {hostname_line}')
                Print.info(f'    System: {system_line}')
                
                results['success'].append({
                    'hostname': hostname,
                    'username': username,
                    'port': port,
                    'region': region
                })
            except Exception as e:
                Print.warn(f'  ✗ Connection failed: {e}')
                results['failed'].append({
                    'hostname': hostname,
                    'username': username,
                    'port': port,
                    'region': region,
                    'error': str(e)
                })
        
        # Print summary
        Print.heading('\nConnection Test Summary')
        Print.info(f'  Successful: {len(results["success"])}/{len(host_info)}')
        Print.info(f'  Failed: {len(results["failed"])}/{len(host_info)}')
        
        if results['failed']:
            Print.warn('\nFailed connections:')
            for failed in results['failed']:
                Print.warn(f'  - {failed["username"]}@{failed["hostname"]}:{failed["port"]} ({failed["region"]})')
                Print.warn(f'    Error: {failed["error"]}')
        
        return results
    
    def install(self):
        """Install Rust and clone the repo on all CloudLab nodes"""
        Print.info('Installing rust and cloning the repo...')
        
        host_info = self.manager.get_host_info()
        cmd = [
            'sudo apt-get update',
            'sudo apt-get install -y tmux',
            'curl https://sh.rustup.rs -sSf | sh -s -- -y',
            'sudo apt-get install -y libclang-dev',
            'sudo apt-get update',
            'sudo apt-get install -y iproute2',
            'sudo apt-get install -y python3-pip',
            # Keep baseline build deps for benchmark compilation.
            'sudo apt-get install -y build-essential cmake clang',
            'source $HOME/.cargo/env',
            'rustup default stable',
            'rustup component add cargo rustc rust-std',
            # Some nodes have a broken rustup cargo proxy; fall back to system cargo.
            'rustup run stable cargo --version || sudo apt-get install -y cargo',
            'rustc --version',
            # Add cargo to PATH permanently
            'echo "export PATH=\\$HOME/.cargo/bin:\\$PATH" >> $HOME/.bashrc',
            'echo "export PATH=\\$HOME/.cargo/bin:\\$PATH" >> $HOME/.profile',
            f'(git clone {self.settings.repo_url} || (cd {self.settings.repo_name} ; git pull))',
            f'cd {self.settings.repo_name}/benchmark && pip3 install -r requirements.txt'
        ]
        
        try:
            # Since each host may have different ports, we need to handle them individually
            # Group all hosts with same connection settings first
            hosts_by_config = {}
            for host in host_info:
                username = host.get('username', 'root')
                hostname = host['hostname']
                port = host.get('port', 22)
                key = (username, port)
                if key not in hosts_by_config:
                    hosts_by_config[key] = []
                hosts_by_config[key].append(hostname)
            
            # Run commands on each group
            for (username, port), hostnames in hosts_by_config.items():
                conn_kwargs = self._get_connection_kwargs({})
                
                # Pass port and timeout as separate parameters, not in connect_kwargs
                # Try connecting to each host individually first to catch connection issues
                valid_hostnames = []
                for hostname in hostnames:
                    try:
                        Print.info(f'Connecting to {username}@{hostname}:{port}...')
                        test_conn = Connection(hostname, user=username, port=port, connect_kwargs=conn_kwargs, connect_timeout=30)
                        test_conn.open()
                        test_conn.close()
                        valid_hostnames.append(hostname)
                        Print.info(f'  [OK] Successfully connected to {hostname}:{port}')
                    except Exception as e:
                        Print.warn(f'  [FAIL] Failed to connect to {hostname}:{port} - {e}')
                        Print.warn(f'    Skipping this host. Please check SSH connection manually.')
                
                # Now run on the valid hosts in the group
                if valid_hostnames:
                    Print.info(f'Running commands on {len(valid_hostnames)} host(s)...')
                    g = Group(*valid_hostnames, user=username, port=port, connect_kwargs=conn_kwargs, connect_timeout=30)
                    g.run(' && '.join(cmd), hide=True)
                else:
                    Print.warn(f'No valid hosts for {username}@{port}, skipping...')
            
            Print.heading(f'Initialized testbed of {len(host_info)} nodes')
        except (GroupException, ExecutionError) as e:
            e = FabricError(e) if isinstance(e, GroupException) else e
            raise BenchError('Failed to install repo on testbed', e)
    
    def status(self, hosts=[]):
        """Check if benchmark processes are running on specified hosts"""
        assert isinstance(hosts, list)
        
        host_info = self.manager.get_host_info()
        host_dict = {h['hostname']: h for h in host_info}
        
        Print.heading('Checking benchmark status on CloudLab nodes...')
        
        # Commands to check running processes
        check_cmd = '''
            primary_pids=$(ps -eo pid=,args= | awk '/(^|\/)(node|target\/release\/node)( |$)/ && / primary( |$)/ && !/awk/ {print $1}') &&
            worker_pids=$(ps -eo pid=,args= | awk '/(^|\/)(node|target\/release\/node)( |$)/ && / worker( |$)/ && !/awk/ {print $1}') &&
            client_pids=$(ps -eo pid=,args= | awk '/(^|\/)(benchmark_client|target\/release\/benchmark_client)( |$)/ && !/awk/ {print $1}') &&
            echo "=== Node Status ===" && 
            echo "Hostname: $(hostname)" &&
            echo "---" &&
            echo "Running processes:" &&
            ([ -n "$primary_pids" ] && echo "  [OK] Primary: running" || echo "  [FAIL] Primary: not running") &&
            ([ -n "$worker_pids" ] && echo "  [OK] Worker: running" || echo "  [FAIL] Worker: not running") &&
            ([ -n "$client_pids" ] && echo "  [OK] Client: running" || echo "  [FAIL] Client: not running") &&
            echo "---" &&
            echo "Process count:" &&
            echo "  Primary: $(printf '%s\n' "$primary_pids" | sed '/^$/d' | wc -l)" &&
            echo "  Worker: $(printf '%s\n' "$worker_pids" | sed '/^$/d' | wc -l)" &&
            echo "  Client: $(printf '%s\n' "$client_pids" | sed '/^$/d' | wc -l)" &&
            echo "---" &&
            echo "Process details:" &&
            ([ -n "$primary_pids" ] && printf '%s\n' "$primary_pids" | xargs ps -fp 2>/dev/null | tail -n +2 || echo "  No primary processes") &&
            ([ -n "$worker_pids" ] && printf '%s\n' "$worker_pids" | xargs ps -fp 2>/dev/null | tail -n +2 || echo "  No worker processes") &&
            ([ -n "$client_pids" ] && printf '%s\n' "$client_pids" | xargs ps -fp 2>/dev/null | tail -n +2 || echo "  No client processes")
        '''
        
        try:
            if not hosts:
                # Check all hosts
                hosts_by_config = {}
                for host in host_info:
                    username = host.get('username', 'root')
                    hostname = host['hostname']
                    port = host.get('port', 22)
                    key = (username, port)
                    if key not in hosts_by_config:
                        hosts_by_config[key] = []
                    hosts_by_config[key].append(hostname)
                
                # Check each group
                for (username, port), hostnames in hosts_by_config.items():
                    conn_kwargs = self._get_connection_kwargs({})
                    g = Group(*hostnames, user=username, port=port, connect_kwargs=conn_kwargs, connect_timeout=30)
                    Print.info(f'Checking {len(hostnames)} host(s) at {username}@{port}...')
                    try:
                        results = g.run(check_cmd, hide=False)
                        # Print results for each host
                        if isinstance(results, dict):
                            for hostname, result in results.items():
                                Print.info(f'\n--- {hostname} ---')
                                if result.stdout:
                                    print(result.stdout)
                        else:
                            if results.stdout:
                                print(results.stdout)
                    except Exception as e:
                        Print.warn(f'Failed to check status: {e}')
            else:
                # Check specific hosts
                hosts_by_config = {}
                for h in hosts:
                    if '@' in h:
                        username, hostname = h.split('@')
                    else:
                        hostname = h
                        username = 'root'
                    
                    host = host_dict.get(hostname, {})
                    username = host.get('username', username)
                    port = host.get('port', 22)
                    key = (username, port)
                    if key not in hosts_by_config:
                        hosts_by_config[key] = []
                    hosts_by_config[key].append(hostname)
                
                for (username, port), hostnames in hosts_by_config.items():
                    conn_kwargs = self._get_connection_kwargs({})
                    g = Group(*hostnames, user=username, port=port, connect_kwargs=conn_kwargs, connect_timeout=30)
                    Print.info(f'Checking {len(hostnames)} host(s) at {username}@{port}...')
                    try:
                        results = g.run(check_cmd, hide=False)
                        if isinstance(results, dict):
                            for hostname, result in results.items():
                                Print.info(f'\n--- {hostname} ---')
                                if result.stdout:
                                    print(result.stdout)
                        else:
                            if results.stdout:
                                print(results.stdout)
                    except Exception as e:
                        Print.warn(f'Failed to check status: {e}')
        except (GroupException, ExecutionError) as e:
            e = FabricError(e) if isinstance(e, GroupException) else e
            Print.warn(f'Some hosts failed to respond: {e}')
    
    def debug_sessions(self, hosts=[]):
        """Debug: Check tmux sessions and capture error messages"""
        Print.heading('Debugging CloudLab nodes - checking tmux sessions...')
        
        host_info = self.manager.get_host_info()
        repo_name = self.settings.repo_name
        
        debug_cmd = f'''
            primary_pids=$(ps -eo pid=,args= | awk '/(^|\/)(node|target\/release\/node)( |$)/ && / primary( |$)/ && !/awk/ {{print $1}}') &&
            worker_pids=$(ps -eo pid=,args= | awk '/(^|\/)(node|target\/release\/node)( |$)/ && / worker( |$)/ && !/awk/ {{print $1}}') &&
            client_pids=$(ps -eo pid=,args= | awk '/(^|\/)(benchmark_client|target\/release\/benchmark_client)( |$)/ && !/awk/ {{print $1}}') &&
            echo "=== Debugging $(hostname) ===" &&
            echo "--- Running Processes ---" &&
            echo "Primary processes:" &&
            ([ -n "$primary_pids" ] && printf '%s\n' "$primary_pids" | xargs ps -fp 2>/dev/null || echo "  No primary processes") &&
            echo "" &&
            echo "Worker processes:" &&
            ([ -n "$worker_pids" ] && printf '%s\n' "$worker_pids" | xargs ps -fp 2>/dev/null || echo "  No worker processes") &&
            echo "" &&
            echo "Client processes:" &&
            ([ -n "$client_pids" ] && printf '%s\n' "$client_pids" | xargs ps -fp 2>/dev/null || echo "  No client processes") &&
            echo "" &&
            echo "--- Log files in {repo_name}/logs ---" &&
            (ls -lh {repo_name}/logs/*.log 2>/dev/null | head -10 || echo "No log files found") &&
            echo "" &&
            echo "--- Recent log content (last 30 lines of each) ---" &&
            for log in {repo_name}/logs/*.log; do
                if [ -f "$log" ]; then
                    echo "=== $(basename $log) ===" &&
                    tail -30 "$log" 2>/dev/null || echo "  Could not read log" &&
                    echo ""
                fi
            done
        '''
        
        try:
            if not hosts:
                # Check all hosts
                hosts_by_config = {}
                for host in host_info:
                    username = host.get('username', 'root')
                    hostname = host['hostname']
                    port = host.get('port', 22)
                    key = (username, port)
                    if key not in hosts_by_config:
                        hosts_by_config[key] = []
                    hosts_by_config[key].append(hostname)
                
                for (username, port), hostnames in hosts_by_config.items():
                    conn_kwargs = self._get_connection_kwargs({})
                    g = Group(*hostnames, user=username, port=port, connect_kwargs=conn_kwargs, connect_timeout=30)
                    Print.info(f'Debugging {len(hostnames)} host(s) at {username}@{port}...')
                    try:
                        results = g.run(debug_cmd, hide=False)
                        if isinstance(results, dict):
                            for hostname, result in results.items():
                                Print.info(f'\n--- {hostname} ---')
                                if result.stdout:
                                    print(result.stdout)
                        else:
                            if results.stdout:
                                print(results.stdout)
                    except Exception as e:
                        Print.warn(f'Failed to debug: {e}')
        except (GroupException, ExecutionError) as e:
            e = FabricError(e) if isinstance(e, GroupException) else e
            Print.warn(f'Some hosts failed to respond: {e}')
    
    def _kill_ports_on_host(self, conn, ports):
        """Kill processes using specific ports on a host"""
        if not ports:
            return
        
        # Create a command to kill processes using these ports
        # Use lsof or fuser to find processes, then kill them
        port_list = ' '.join(str(p) for p in sorted(ports))
        kill_ports_cmd = f'''
            # Kill processes using specified ports
            for port in {port_list}; do
                # Try using lsof first (more common)
                if command -v lsof >/dev/null 2>&1; then
                    lsof -ti:$port 2>/dev/null | xargs kill -9 2>/dev/null || true
                # Fallback to fuser
                elif command -v fuser >/dev/null 2>&1; then
                    fuser -k $port/tcp 2>/dev/null || true
                # Last resort: use ss/netstat to find PIDs
                elif command -v ss >/dev/null 2>&1; then
                    ss -tlnp 2>/dev/null | grep ":$port " | grep -oP 'pid=\\K[0-9]+' | xargs kill -9 2>/dev/null || true
                elif command -v netstat >/dev/null 2>&1; then
                    netstat -tlnp 2>/dev/null | grep ":$port " | awk '{{print $7}}' | cut -d'/' -f1 | xargs kill -9 2>/dev/null || true
                fi
            done
            true
        '''
        try:
            conn.run(kill_ports_cmd, hide=True, warn=True, shell='/bin/bash')
        except:
            pass  # Ignore errors in port killing
    
    def _get_ports_from_committee(self, committee, faults):
        """Extract all ports that will be used by the committee"""
        ports_by_host = {}  # {hostname: set of ports}
        host_info = self.manager.get_host_info()
        
        # Create a mapping from IP to hostname
        ip_to_hostname = {}
        for host in host_info:
            hostname = host['hostname']
            # Try to resolve hostname to IP
            try:
                import socket
                ip = socket.gethostbyname(hostname)
                ip_to_hostname[ip] = hostname
                # Also map hostname itself in case it's already an IP
                ip_to_hostname[hostname] = hostname
            except:
                # If resolution fails, use hostname as-is
                ip_to_hostname[hostname] = hostname
        
        # Extract all addresses from committee JSON structure
        # Skip faulty nodes
        authorities = list(committee.json['authorities'].items())
        if faults > 0:
            authorities = authorities[:-faults]
        
        for name, authority in authorities:
            # Primary addresses
            primary = authority['primary']
            for addr_type, address in primary.items():
                ip, port = address.rsplit(':', 1)
                port = int(port)
                hostname = ip_to_hostname.get(ip, ip)
                if hostname not in ports_by_host:
                    ports_by_host[hostname] = set()
                ports_by_host[hostname].add(port)
            
            # Worker addresses
            workers = authority['workers']
            for worker_id, worker in workers.items():
                for addr_type, address in worker.items():
                    ip, port = address.rsplit(':', 1)
                    port = int(port)
                    hostname = ip_to_hostname.get(ip, ip)
                    if hostname not in ports_by_host:
                        ports_by_host[hostname] = set()
                    ports_by_host[hostname].add(port)
        
        return ports_by_host
    
    def kill(self, hosts=[], delete_logs=False, committee=None, faults=0):
        """Stop execution on specified hosts"""
        assert isinstance(hosts, list)
        assert isinstance(delete_logs, bool)
        
        host_info = self.manager.get_host_info()
        host_dict = {h['hostname']: h for h in host_info}
        delete_logs_cmd = CommandMaker.clean_logs() if delete_logs else 'true'
        # Kill benchmark processes by pattern matching
        # This will kill all processes matching the benchmark patterns
        kill_cmd = '''
            # Kill any running benchmark processes
            pkill -9 -f "node.*primary" 2>/dev/null || true
            pkill -9 -f "node.*worker" 2>/dev/null || true
            pkill -9 -f "benchmark_client" 2>/dev/null || true
            # Also kill any wrapper scripts that might still be running
            pkill -9 -f "/tmp/run_(primary|worker|client)-" 2>/dev/null || true
            # Kill any in-flight cargo build jobs spawned during benchmark setup
            pkill -9 -f "cargo build" 2>/dev/null || true
            pkill -9 -f "/.cargo/bin/cargo" 2>/dev/null || true
            pkill -9 -f "rustc" 2>/dev/null || true
            pkill -9 -f "cc " 2>/dev/null || true
            pkill -9 -f "clang" 2>/dev/null || true
            pkill -9 -f "build-script-build" 2>/dev/null || true
            true
        '''
        # Cleanup database directories and lock files
        cleanup_db_cmd = 'rm -rf .db-* 2>/dev/null || true'
        cmd = [delete_logs_cmd, kill_cmd, cleanup_db_cmd]
        
        # If committee is provided, also kill processes using the ports
        ports_by_host = {}
        if committee is not None:
            ports_by_host = self._get_ports_from_committee(committee, faults)
        
        try:
            if not hosts:
                # Group hosts by (username, port) to use Group efficiently
                hosts_by_config = {}
                for host in host_info:
                    username = host.get('username', 'root')
                    hostname = host['hostname']
                    port = host.get('port', 22)
                    key = (username, port)
                    if key not in hosts_by_config:
                        hosts_by_config[key] = []
                    hosts_by_config[key].append(hostname)
                
                # Run on each group
                for (username, port), hostnames in hosts_by_config.items():
                    conn_kwargs = self._get_connection_kwargs({})
                    g = Group(*hostnames, user=username, port=port, connect_kwargs=conn_kwargs)
                    # Use warn=True since pkill may not find processes
                    g.run(' && '.join(cmd), hide=True, warn=True)
                    
                    # Kill processes using committee ports on these hosts
                    if ports_by_host:
                        for hostname in hostnames:
                            if hostname in ports_by_host:
                                ports = ports_by_host[hostname]
                                if ports:
                                    conn = Connection(hostname, user=username, port=port, connect_kwargs=conn_kwargs)
                                    self._kill_ports_on_host(conn, ports)
            else:
                # Handle specific hosts (can be strings or dicts)
                hosts_by_config = {}
                for h in hosts:
                    # Handle both string and dict formats
                    if isinstance(h, dict):
                        hostname = h['hostname']
                        username = h.get('username', 'root')
                        port = h.get('port', 22)
                    else:
                        # Extract hostname from host string
                        hostname = h.split('@')[1]
                        username = h.split('@')[0]
                        port = 22
                    key = (username, port)
                    if key not in hosts_by_config:
                        hosts_by_config[key] = []
                    hosts_by_config[key].append(hostname)
                
                # Run on each group
                for (username, port), hostnames in hosts_by_config.items():
                    conn_kwargs = self._get_connection_kwargs({})
                    g = Group(*hostnames, user=username, port=port, connect_kwargs=conn_kwargs)
                    # Use warn=True since pkill may not find processes
                    g.run(' && '.join(cmd), hide=True, warn=True)
                    
                    # Kill processes using committee ports on these hosts
                    if ports_by_host:
                        for hostname in hostnames:
                            if hostname in ports_by_host:
                                ports = ports_by_host[hostname]
                                if ports:
                                    conn = Connection(hostname, user=username, port=port, connect_kwargs=conn_kwargs)
                                    self._kill_ports_on_host(conn, ports)
        except GroupException as e:
            # Don't fail if kill commands have errors - processes might not exist
            Print.warn(f'Some kill commands failed (this is OK if processes don\'t exist): {e}')
            raise BenchError('Failed to kill nodes', FabricError(e))
    
    def _select_hosts(self, bench_parameters):
        """Select hosts based on benchmark parameters"""
        host_info = self.manager.get_host_info()
        
        # Collocate primary and workers on the same machine
        if bench_parameters.collocate:
            nodes = max(bench_parameters.nodes)
            if len(host_info) < nodes:
                error_msg = f'Not enough hosts: need {nodes}, have {len(host_info)}'
                raise BenchError(error_msg, ValueError(error_msg))
            return host_info[:nodes]
        else:
            # One node per machine (primary + workers on separate machines)
            nodes = max(bench_parameters.nodes)
            workers = bench_parameters.workers
            total_machines = nodes * (1 + workers)  # primary + workers
            if len(host_info) < total_machines:
                error_msg = f'Not enough hosts: need {total_machines}, have {len(host_info)}'
                raise BenchError(error_msg, ValueError(error_msg))
            return host_info[:total_machines]
    
    def _modify_attack_rs(self, hosts, trigger_attack):
        """Modify TRIGGER_NETWORK_INTERRUPT in adversary/src/attack.rs on remote hosts"""
        if trigger_attack is None:
            return  # No modification needed
        
        Print.info(f'Modifying TRIGGER_NETWORK_INTERRUPT to {trigger_attack} on all nodes...')
        repo_name = self.settings.repo_name
        attack_rs_path = f'{repo_name}/adversary/src/attack.rs'
        
        # Use sed command instead of Python script to avoid escaping issues
        trigger_value_str = 'true' if trigger_attack else 'false'
        # sed command to replace the value (match the specific line pattern)
        # Match: pub const TRIGGER_NETWORK_INTERRUPT: bool = false;
        # or:    pub const TRIGGER_NETWORK_INTERRUPT: bool = true;
        # Replace with the desired value
        sed_cmd = f"sed -i 's/TRIGGER_NETWORK_INTERRUPT: bool = true/TRIGGER_NETWORK_INTERRUPT: bool = {trigger_value_str}/; s/TRIGGER_NETWORK_INTERRUPT: bool = false/TRIGGER_NETWORK_INTERRUPT: bool = {trigger_value_str}/' {attack_rs_path}"
        
        try:
            # Group hosts by (username, port) to use Group efficiently
            hosts_by_config = {}
            for host in hosts:
                username = host.get('username', 'root')
                hostname = host['hostname']
                port = host.get('port', 22)
                key = (username, port)
                if key not in hosts_by_config:
                    hosts_by_config[key] = []
                hosts_by_config[key].append(hostname)
            
            # Run modification command on each group
            for (username, port), hostnames in hosts_by_config.items():
                conn_kwargs = self._get_connection_kwargs({})
                g = Group(*hostnames, user=username, port=port, connect_kwargs=conn_kwargs, connect_timeout=30)
                # Check if repo directory exists first, then verify file exists and modify it
                # If file doesn't exist, warn but don't fail (repo might not be cloned yet)
                cmd = f'test -d {repo_name} && test -f {attack_rs_path} && ({sed_cmd} && echo "Successfully modified {attack_rs_path}") || (echo "Warning: {attack_rs_path} not found - repository may need to be installed first" && exit 0)'
                result = g.run(cmd, hide=True, warn=True)
                # Check if any host failed (but allow warnings)
                if isinstance(result, dict):
                    for hostname, res in result.items():
                        if not res.ok and 'Warning' not in res.stdout:
                            Print.warn(f'Failed to modify attack.rs on {hostname}: {res.stderr}')
                elif not result.ok and 'Warning' not in result.stdout:
                    Print.warn(f'Failed to modify attack.rs: {result.stderr}')
        except (GroupException, ExecutionError) as e:
            # Don't fail the entire benchmark if attack.rs modification fails
            Print.warn(f'Could not modify attack.rs (this is OK if repository is not installed yet): {e}')
    
    def _update(self, hosts, collocate, trigger_attack=None):
        """Update code on all hosts"""
        Print.info('Updating code on all nodes...')
        repo_name = self.settings.repo_name
        branch = self.settings.branch
        
        cmd = [
            f'cd {repo_name} || (echo "Repository {repo_name} not found. Please run: fab cloudlab-install" && exit 1)',
            'git fetch',
            f'git checkout {branch}',
            'git pull',
            # Recover from corrupted rustup metadata (e.g. empty settings.toml).
            'if [ -f "$HOME/.rustup/settings.toml" ] && ! grep -q "^version" "$HOME/.rustup/settings.toml"; '
            'then echo "Detected corrupted rustup settings.toml; resetting it"; rm -f "$HOME/.rustup/settings.toml"; fi',
            # Fully reinstall rustup/cargo when rustup is broken or missing.
            'if ! rustup --version >/dev/null 2>&1; then '
            'echo "rustup not healthy; performing full reinstall"; '
            'rm -rf "$HOME/.rustup" "$HOME/.cargo"; '
            'curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain stable; '
            'fi',
            # Ensure rustup/cargo are on PATH in the current shell (no subshell).
            'if [ -f "$HOME/.cargo/env" ]; then . "$HOME/.cargo/env"; fi; export PATH="$HOME/.cargo/bin:$PATH"',
            'command -v rustup >/dev/null 2>&1 || (echo "rustup not found after setup" && exit 1)',
            'command -v cargo >/dev/null 2>&1 || (echo "cargo not found after setup" && exit 1)',
            'rustup toolchain install stable',
            'rustup default stable',
            'rustup component add cargo rustc rust-std || true',
            # Build prerequisites and diagnostics for common cc-rs failures.
            'if ! command -v cc >/dev/null 2>&1; then '
            'echo "C compiler not found; installing build-essential"; '
            'sudo apt-get update && sudo apt-get install -y build-essential; '
            'fi',
            # rocksdb -> librocksdb-sys may pull libz-sys / bzip2-sys. Bundled zlib (zutil.c) often
            # fails on CloudLab with empty cc stderr; system zlib via pkg-config avoids that build.
            'echo "Installing zlib/bzip2 dev + pkg-config for libz-sys/libbz2-sys"; '
            'sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq && '
            'sudo DEBIAN_FRONTEND=noninteractive apt-get install -y zlib1g-dev libbz2-dev pkg-config',
            'echo "Pre-build diagnostics:"',
            'df -h . || true',
            'df -i . || true',
            'cc --version || true',
            'cargo build --release --features benchmark',
            # Keep the node source directory intact; only ensure benchmark_client launcher exists.
            'rm -f benchmark_client 2>/dev/null || true',
            'test -f ./target/release/benchmark_client && ln -sf ./target/release/benchmark_client ./benchmark_client || true',
            'test -x ./target/release/node',
            'test -x ./target/release/benchmark_client'
        ]
        
        # Modify attack.rs AFTER updating the code (so the file exists)
        # This ensures the repository is cloned and up-to-date first
        if trigger_attack is not None:
            # We'll modify attack.rs after git operations complete
            pass
        
        try:
            # Group hosts by (username, port) to use Group efficiently
            hosts_by_config = {}
            for host in hosts:
                username = host.get('username', 'root')
                hostname = host['hostname']
                port = host.get('port', 22)
                key = (username, port)
                if key not in hosts_by_config:
                    hosts_by_config[key] = []
                hosts_by_config[key].append(hostname)
            
            # Run commands on each group
            for (username, port), hostnames in hosts_by_config.items():
                conn_kwargs = self._get_connection_kwargs({})
                g = Group(*hostnames, user=username, port=port, connect_kwargs=conn_kwargs, connect_timeout=60)
                g.run(' && '.join(cmd), hide=True)
                
                # Modify attack.rs AFTER git operations (so the file exists)
                if trigger_attack is not None:
                    # Create a subset of hosts for modification
                    modify_hosts = [{'hostname': h, 'username': username, 'port': port} for h in hostnames]
                    self._modify_attack_rs(modify_hosts, trigger_attack)
        except (GroupException, ExecutionError) as e:
            if isinstance(e, GroupException):
                _print_fabric_group_diagnostics(
                    e.result,
                    "Failed to update nodes — full output per host (git/rustup/cargo):",
                )
                e = FabricError(e)
            raise BenchError('Failed to update nodes', e)
    
    def _config(self, hosts, node_parameters, bench_parameters):
        """Generate and upload configuration files"""
        Print.info('Generating configuration files...')
        
        # Cleanup all local configuration files (same as remote.py)
        cmd = CommandMaker.cleanup()
        subprocess.run([cmd], shell=True, stderr=subprocess.DEVNULL)
        
        # Try to compile locally, but fall back to remote key generation if cargo is not available
        keys = []
        key_files = [PathMaker.key_file(i) for i in range(len(hosts))]
        local_compilation_success = False
        
        # Check if node binary exists before attempting local compilation
        # PathMaker paths are relative to benchmark/ directory (not benchmark/benchmark/)
        # So '../target/release' means 'target/release' from project root
        # And '../node' means 'node' from project root
        node_crate_path = PathMaker.node_crate_path()
        binary_path = PathMaker.binary_path()
        
        # Check multiple possible locations for node binary
        # Code runs from benchmark/ directory
        # 1. ../target/release/node (actual binary from project root)
        # 2. ./node (symlink in benchmark/ directory if exists)
        # 3. node (if in current directory)
        import os
        current_dir = Path.cwd()
        node_paths = [
            '../target/release/node',  # From benchmark/ to project root
            './node',  # Symlink in benchmark/ directory
            'node',  # If in current directory
            str(Path(binary_path) / 'node')  # Using PathMaker path
        ]
        
        # Check if any path exists (using os.path for proper symlink resolution)
        node_exists = False
        for path_str in node_paths:
            # First check if path exists at all (including broken symlinks)
            if os.path.lexists(path_str):
                # If it's a symlink, we need to resolve it relative to the symlink's directory
                if os.path.islink(path_str):
                    # Get the symlink's directory and resolve the target relative to it
                    symlink_dir = os.path.dirname(os.path.abspath(path_str))
                    target = os.readlink(path_str)
                    # Resolve target relative to symlink directory
                    if not os.path.isabs(target):
                        resolved = os.path.normpath(os.path.join(symlink_dir, target))
                    else:
                        resolved = target
                    if os.path.exists(resolved) and os.path.isfile(resolved):
                        node_exists = True
                        break
                # If it's a regular file, it exists
                elif os.path.isfile(path_str):
                    node_exists = True
                    break
            # Also check with exists() for non-symlink files
            elif os.path.exists(path_str) and os.path.isfile(path_str):
                node_exists = True
                break
        
        if not node_exists:
            Print.info('Node binary not found locally, will generate keys on remote nodes...')
        else:
            try:
                # Recompile the latest code (same as remote.py)
                # node_crate_path from PathMaker is '../node' relative to benchmark/ directory
                # This is correct: from benchmark/ to project root/node
                cmd = CommandMaker.compile().split()
                subprocess.run(cmd, check=True, cwd=node_crate_path)
                local_compilation_success = True
                
                # Create alias for the client and nodes binary (same as remote.py)
                # This creates symlinks in the current directory (benchmark/)
                # binary_path is '../target/release' relative to benchmark/ directory
                # This is correct: from benchmark/ to project root/target/release
                cmd = CommandMaker.alias_binaries(binary_path)
                subprocess.run([cmd], shell=True)
                
                # Generate keys locally
                # CommandMaker.generate_key uses './node', so we need to be in a directory where ./node exists
                # After alias_binaries, ./node should exist in current directory (benchmark/)
                # Get the current working directory (benchmark/)
                current_dir = Path.cwd()
                for filename in key_files:
                    cmd = CommandMaker.generate_key(filename).split()
                    # Run from current directory where ./node should exist after alias_binaries
                    subprocess.run(cmd, check=True, cwd=current_dir)
                    keys += [Key.from_file(filename)]
                    
            except (FileNotFoundError, subprocess.CalledProcessError) as e:
                # If cargo is not available locally (e.g., on Windows), generate keys on remote nodes
                Print.warn(f'Local compilation failed (this is OK if cargo is not available): {e}')
                Print.info('Generating keys on remote nodes instead...')
        
        if not local_compilation_success:
            Print.info('Generating keys on remote nodes instead...')
            Print.info(f'Need to generate {len(key_files)} key files for {len(hosts)} hosts')
            
            # Generate keys on the first remote host (they're the same for all)
            repo_name = self.settings.repo_name
            first_host = hosts[0]
            username = first_host.get('username', 'root')
            hostname = first_host['hostname']
            port = first_host.get('port', 22)
            conn_kwargs = self._get_connection_kwargs({})
            
            try:
                Print.info(f'Connecting to {username}@{hostname}:{port} to generate keys...')
                conn = Connection(hostname, user=username, port=port, 
                                 connect_kwargs=conn_kwargs, connect_timeout=30)
                conn.open()
                
                # Generate keys on remote node (code should already be compiled from _update)
                for i, key_file in enumerate(key_files):
                    Print.info(f'Generating key {i+1}/{len(key_files)}: {key_file}')
                    # Generate into the repo root after `cd {repo_name}`.
                    remote_key_filename = key_file
                    remote_key_path = f'{repo_name}/{key_file}'
                    # Generate key using the compiled node binary
                    # The binary should exist after _update compiles the code
                    cmd = f'cd {repo_name} && ./node generate_keys --filename {remote_key_filename}'
                    Print.info(f'Running command: {cmd}')
                    result = conn.run(cmd, hide=True, warn=True)
                    if not result.ok:
                        # Try with target/release/node if ./node doesn't exist
                        Print.info(f'First attempt failed, trying with target/release/node...')
                        cmd = f'cd {repo_name} && ./target/release/node generate_keys --filename {remote_key_filename}'
                        result = conn.run(cmd, hide=True)
                    
                    if not result.ok:
                        error_msg = f'Failed to generate key file {key_file} on remote node: {result.stderr}'
                        Print.error(f'  ✗ {error_msg}')
                        raise BenchError(error_msg, RuntimeError(error_msg))
                    
                    Print.info(f'  ✓ Key generated on remote node')
                    
                    # Download the key file
                    Print.info(f'Downloading key file {key_file}...')
                    try:
                        conn.get(remote_key_path, key_file)
                        Print.info(f'  ✓ Key file downloaded: {key_file}')
                    except Exception as e:
                        error_msg = f'Failed to download key file {key_file} from remote node: {e}'
                        Print.error(f'  ✗ {error_msg}')
                        raise BenchError(error_msg, e)
                
                # Load all keys and verify we have the correct number
                Print.info(f'Loading {len(key_files)} key files...')
                for key_file in key_files:
                    key_path = Path(key_file)
                    if not key_path.exists():
                        error_msg = f'Key file {key_file} was not downloaded successfully'
                        Print.error(f'  ✗ {error_msg}')
                        raise BenchError(error_msg, FileNotFoundError(error_msg))
                    Print.info(f'  ✓ Loading key from {key_file}')
                    keys += [Key.from_file(key_file)]
                
                Print.info(f'Successfully generated and loaded {len(keys)} keys')
                
                if len(keys) != len(hosts):
                    error_msg = (
                        f'Generated {len(keys)} keys but need {len(hosts)} keys for {len(hosts)} hosts. '
                        f'Key files: {key_files}'
                    )
                    raise BenchError(error_msg, ValueError(error_msg))
                
                conn.close()
                    
            except Exception as e:
                error_msg = f'Failed to generate keys on remote nodes. Please ensure the code is compiled on remote nodes. Error: {e}'
                Print.warn(error_msg)
                Print.warn(f'Keys generated so far: {len(keys)}/{len(key_files)}')
                Print.warn(f'Key files expected: {key_files}')
                if hasattr(e, '__traceback__'):
                    import traceback
                    Print.warn('Full traceback:')
                    traceback.print_exc()
                raise BenchError(error_msg, e)
        
        # Final check: ensure we have keys before proceeding
        if len(keys) == 0:
            error_msg = (
                f'No keys were generated. Local compilation failed and remote generation also failed. '
                f'Please ensure either: (1) node binary exists locally, or (2) remote nodes have compiled code.'
            )
            raise BenchError(error_msg, RuntimeError(error_msg))
        
        # Create addresses dict for Committee
        # Format: {name: [primary_host, worker1_host, worker2_host, ...]}
        addresses = OrderedDict()
        
        # Verify that we have the same number of keys and hosts
        if len(keys) != len(hosts):
            error_msg = (
                f'Mismatch between number of keys ({len(keys)}) and hosts ({len(hosts)}). '
                f'Expected {len(hosts)} keys for {len(hosts)} hosts.'
            )
            raise BenchError(error_msg, ValueError(error_msg))
        
        for i, key in enumerate(keys):
            host = hosts[i]
            hostname = host['hostname']
            # Remove port if present
            if ':' in hostname:
                hostname = hostname.split(':')[0]
            
            # For collocated setup, primary and workers are on the same host
            if bench_parameters.collocate:
                worker_hosts = [hostname] * bench_parameters.workers
            else:
                # For non-collocated, each worker is on a different host
                # This is simplified - you may need to adjust based on your setup
                worker_hosts = [hostname] * bench_parameters.workers
            
            addresses[key.name] = [hostname] + worker_hosts
        
        # Verify all address lists have the same length before creating Committee
        lengths = [len(x) for x in addresses.values()]
        if len(set(lengths)) != 1:
            error_msg = (
                f'Address lists have inconsistent lengths: {lengths}. '
                f'All nodes must have the same number of workers. '
                f'Addresses: {dict(addresses)}'
            )
            raise BenchError(error_msg, ValueError(error_msg))
        
        sigma = node_parameters.json.get('sigma', 1)
        kappa = node_parameters.json.get('kappa', 2)
        reference = node_parameters.json.get('reference', 4)
        coverage = node_parameters.json.get('coverage', 7)
        committee = Committee(
            addresses,
            self.settings.base_port,
            sigma,
            kappa,
            reference,
            coverage,
        )
        committee.print(PathMaker.committee_file())
        
        node_parameters.print(PathMaker.parameters_file())  # 改为 print() 而不是 save()
        
        # Upload files to all hosts
        repo_name = self.settings.repo_name
        files_to_upload = [
            (PathMaker.committee_file(), f'{repo_name}/.committee.json'),
            (PathMaker.parameters_file(), f'{repo_name}/.parameters.json'),
        ]
        
        # Upload keys
        for i, key in enumerate(keys):
            files_to_upload.append(
                (PathMaker.key_file(i), f'{repo_name}/{PathMaker.key_file(i)}')
            )
        
        Print.info('Uploading configuration files...')
        try:
            for host in hosts:
                username = host.get('username', 'root')
                hostname = host['hostname']
                port = host.get('port', 22)
                conn_kwargs = self._get_connection_kwargs({})
                conn = Connection(hostname, user=username, port=port, connect_kwargs=conn_kwargs)
                current_local = None
                current_remote = None
                current_local_size = None
                try:
                    for local, remote in files_to_upload:
                        current_local = local
                        current_remote = remote
                        local_path = Path(local)
                        current_local_size = local_path.stat().st_size if local_path.exists() else None
                        Print.info(
                            f'Uploading {local} ({current_local_size} bytes) '
                            f'to {username}@{hostname}:{remote}'
                        )
                        conn.put(local, remote)
                except Exception as upload_error:
                    diagnostics = []
                    if current_remote:
                        remote_parent = str(Path(current_remote).parent)
                        # Gather quick remote diagnostics to explain common upload failures.
                        cmd = (
                            f'echo "pwd=$(pwd)"; '
                            f'echo "remote_parent={shlex.quote(remote_parent)}"; '
                            f'ls -ld {shlex.quote(remote_parent)} || true; '
                            f'df -h {shlex.quote(remote_parent)} || true; '
                            f'df -i {shlex.quote(remote_parent)} || true'
                        )
                        result = conn.run(cmd, hide=True, warn=True)
                        diagnostics.append(result.stdout.strip())

                    details = (
                        f'Upload failed on host {username}@{hostname}:{port}. '
                        f'local={current_local}, remote={current_remote}, '
                        f'local_size={current_local_size}. '
                        f'Original error: {upload_error}'
                    )
                    if diagnostics:
                        details += f'\nRemote diagnostics:\n{diagnostics[0]}'
                    raise BenchError(details, upload_error)
                finally:
                    conn.close()
        except Exception as e:
            raise BenchError('Failed to upload configuration files', e)
        
        return committee
    
    def _logs(self, committee, faults, max_workers=1):
        """Download logs from all hosts using download_logs.py"""
        Print.info('Downloading logs...')
        
        # Get benchmark directory (parent of benchmark/benchmark/)
        benchmark_dir = Path(__file__).parent.parent
        download_logs_script = benchmark_dir / 'download_logs.py'
        
        if not download_logs_script.exists():
            Print.error(f'download_logs.py not found at {download_logs_script}')
            Print.error('Falling back to basic log download...')
            # Fallback: create logs directory and return parser
            Path(PathMaker.logs_path()).mkdir(parents=True, exist_ok=True)
            return LogParser.process(PathMaker.logs_path(), faults=faults)
        
        # Run download_logs.py to download all logs
        try:
            import sys
            Print.info(f'Running download_logs.py with max_workers={max_workers}...')
            result = subprocess.run(
                [sys.executable, str(download_logs_script), '--max-workers', str(max_workers)],
                cwd=str(benchmark_dir),
                capture_output=False,  # Show output in real-time
                text=True
            )
            
            if result.returncode == 0:
                Print.info('✓ download_logs.py completed successfully')
            else:
                Print.warn(f'⚠ download_logs.py exited with code {result.returncode}')
        except Exception as e:
            Print.warn(f'⚠ Failed to run download_logs.py: {e}')
            Print.warn('Logs may be incomplete')
        
        # After downloading logs, run processing script
        Print.info('=' * 60)
        Print.info('Processing logs...')
        Print.info('=' * 60)
        
        try:
            run_benchmark_script = benchmark_dir / 'run_cloudlab_benchmark.py'
            
            if run_benchmark_script.exists():
                Print.info('Running run_cloudlab_benchmark.py --no-run to process logs...')
                result = subprocess.run(
                    [sys.executable, str(run_benchmark_script), '--no-run'],
                    cwd=str(benchmark_dir),
                    capture_output=False,  # Show output in real-time
                    text=True
                )
                if result.returncode == 0:
                    Print.info('✓ run_cloudlab_benchmark.py --no-run completed successfully')
                else:
                    Print.warn(f'⚠ run_cloudlab_benchmark.py --no-run exited with code {result.returncode}')
            else:
                Print.warn(f'⚠ run_cloudlab_benchmark.py not found at {run_benchmark_script}')
        except Exception as e:
            Print.warn(f'⚠ Failed to run run_cloudlab_benchmark.py --no-run: {e}')
        
        Print.info('=' * 60)
        
        # Parse and return logs
        return LogParser.process(PathMaker.logs_path(), faults=faults)
    
    def _background_run(self, host_info, command, log_file):
        """Run a command in the background using nohup on a remote host"""
        from os.path import basename, splitext, dirname
        name = splitext(basename(log_file))[0]
        repo_name = self.settings.repo_name
        # remote_log is the full path from repo root
        remote_log = f'{repo_name}/{log_file}'
        # log_file_relative is the path relative to repo directory (after cd)
        log_file_relative = log_file
        
        username = host_info.get('username', 'root')
        hostname = host_info['hostname']
        port = host_info.get('port', 22)
        conn_kwargs = self._get_connection_kwargs({})
        
        Print.info(f'Starting {name} on {hostname}...')
        c = Connection(hostname, user=username, port=port, connect_kwargs=conn_kwargs, connect_timeout=30)
        try:
            # Ensure repo binaries exist on this host. Some hosts only have target/release/*
            # and some may need a one-time build; normalize by creating root-level symlinks.
            test_cmd = (
                f'cd {repo_name} && '
                '((test -x ./target/release/node) && '
                '(test -x ./benchmark_client || test -x ./target/release/benchmark_client) && '
                'echo "Binaries found") || echo "Binaries missing"'
            )
            test_result = c.run(test_cmd, hide=True, warn=True)
            if 'Binaries missing' in test_result.stdout:
                Print.warn(f'  ⚠ Binaries not found in {repo_name} on {hostname}; attempting build...')
                ensure_binaries_cmd = f'''cd {repo_name} && (
if [ -f "$HOME/.cargo/env" ]; then . "$HOME/.cargo/env"; fi
if [ ! -f ./target/release/node ] || [ ! -f ./target/release/benchmark_client ]; then
    if rustup run stable cargo --version >/dev/null 2>&1; then
        rustup run stable cargo build --release --bin node --bin benchmark_client
    else
        cargo build --release --bin node --bin benchmark_client
    fi
fi
[ -f ./target/release/benchmark_client ] && [ ! -f ./benchmark_client ] && ln -sf ./target/release/benchmark_client ./benchmark_client || true
test -x ./target/release/node && (test -x ./benchmark_client || test -x ./target/release/benchmark_client)
)'''
                ensure_result = c.run(ensure_binaries_cmd, hide=True, warn=True)
                if not ensure_result.ok:
                    error_msg = (
                        f'Binaries are missing on {hostname} and automatic build failed. '
                        'Please run cloudlab-install to compile binaries on all nodes.'
                    )
                    raise BenchError(error_msg, RuntimeError((ensure_result.stderr or ensure_result.stdout).strip()))
            
            # Ensure log directory exists
            from os.path import dirname
            log_dir = f'{repo_name}/{dirname(log_file)}' if dirname(log_file) else repo_name
            c.run(f'mkdir -p {log_dir}', hide=True)
            
            # Create a wrapper script that will run the command
            # The script will handle logging and ensure the process stays running
            script_path = f'/tmp/run_{name}.sh'
            
            # Extract store path from command for cleanup
            store_match = re.search(r'--store\s+(\S+)', command)
            store_path = store_match.group(1) if store_match else None
            
            # Resolve command binary path on remote host. In repo root, "node" is a directory,
            # so "./node" may be invalid; prefer target/release binaries.
            resolved_command = command
            if command.startswith('./node '):
                resolved_command = command.replace('./node ', '${NODE_BIN} ', 1)
            elif command.startswith('./benchmark_client '):
                resolved_command = command.replace('./benchmark_client ', '${CLIENT_BIN} ', 1)

            # Write script with better error handling
            # Use relative path after cd to repo directory
            # log_file is already relative (e.g., "logs/client-0-0.log")
            cleanup_store = f'rm -rf {store_path} 2>/dev/null || true' if store_path else ''
            script_cmd = f'''cat > {script_path} << 'SCRIPTEOF'
#!/bin/bash
# Change to repo directory first
cd {repo_name} || {{
    echo "ERROR: Failed to cd to {repo_name}"
    echo "Current directory: $(pwd)"
    exit 1
}}

# Ensure log directory exists (relative to repo directory)
mkdir -p $(dirname {log_file}) 2>/dev/null || true

# Cleanup database directory and lock files before starting
{cleanup_store}

# Resolve runtime binaries (for client/worker/primary)
if [[ "{name}" == client-* ]]; then
    if [ -x "./benchmark_client" ]; then
        CLIENT_BIN="./benchmark_client"
    elif [ -x "./target/release/benchmark_client" ]; then
        CLIENT_BIN="./target/release/benchmark_client"
    else
        echo "ERROR: benchmark_client not found" | tee {log_file}
        echo "Looking in: $(pwd)" | tee -a {log_file}
        echo "Files in current dir: $(ls -la | head -10)" | tee -a {log_file}
        exit 1
    fi
elif [[ "{name}" == worker-* ]] || [[ "{name}" == primary-* ]]; then
    if [ -x "./target/release/node" ]; then
        NODE_BIN="./target/release/node"
    elif [ -x "./node" ] && [ ! -d "./node" ]; then
        NODE_BIN="./node"
    else
        echo "ERROR: node binary not found" | tee {log_file}
        echo "Looking in: $(pwd)" | tee -a {log_file}
        echo "Files in current dir: $(ls -la | head -10)" | tee -a {log_file}
        exit 1
    fi
fi

# Open log file and redirect stdout/stderr to it BEFORE exec
# This ensures the file is created and opened before the process starts
# Use relative path since we're already in the repo directory
exec > {log_file} 2>&1

# Execute the command
# Use exec to replace shell with the actual process
exec {resolved_command}
SCRIPTEOF'''
            script_write_result = c.run(script_cmd, hide=True, warn=True)
            if not script_write_result.ok:
                Print.warn(f'  ✗ Failed to create script: {script_write_result.stderr}')
                error_msg = f'Failed to create script for {name} on {hostname}'
                raise BenchError(error_msg, RuntimeError(error_msg))
            
            chmod_result = c.run(f'chmod +x {script_path}', hide=True, warn=True)
            if not chmod_result.ok:
                Print.warn(f'  ✗ Failed to make script executable: {chmod_result.stderr}')
                error_msg = f'Failed to make script executable for {name} on {hostname}'
                raise BenchError(error_msg, RuntimeError(error_msg))
            
            # Verify script was created correctly
            verify_script = c.run(f'test -f {script_path} && echo "OK" || echo "FAIL"', hide=True, warn=True)
            if 'FAIL' in verify_script.stdout:
                Print.warn(f'  ✗ Script file {script_path} was not created')
                error_msg = f'Script file not created for {name} on {hostname}'
                raise BenchError(error_msg, FileNotFoundError(error_msg))
            
            # Use nohup to run the script in background
            # Use setsid to create a new session and detach from terminal
            # Redirect all output to /dev/null since script handles its own logging
            nohup_cmd = f'setsid nohup bash {script_path} </dev/null >/dev/null 2>&1 & echo $!'
            nohup_result = c.run(nohup_cmd, hide=True, warn=True)
            
            if not nohup_result.ok:
                Print.warn(f'  ✗ Failed to start {name}: {nohup_result.stderr}')
                error_msg = f'Failed to start {name} on {hostname}'
                raise BenchError(error_msg, RuntimeError(error_msg))
            
            pid = nohup_result.stdout.strip()
            if not pid or not pid.isdigit():
                Print.warn(f'  ✗ Failed to get PID for {name}')
                error_msg = f'Failed to start {name} on {hostname}'
                raise BenchError(error_msg, ValueError(error_msg))
            
            Print.info(f'  ✓ {name} started on {hostname} (PID: {pid})')
            
            # Wait a bit and verify the process is actually running
            sleep(1.0)
            check_cmd = f'ps -p {pid} >/dev/null 2>&1 && echo "Running" || echo "Not running"'
            check_result = c.run(check_cmd, hide=True, warn=True)
            
            if 'Not running' in check_result.stdout:
                # Process exited, check the log for errors
                Print.warn(f'  ⚠ Process {pid} exited immediately, checking logs...')
                
                # Check if script exists and can be read
                script_check = c.run(f'test -f {script_path} && cat {script_path} || echo "Script not found"', hide=True, warn=True)
                if 'Script not found' not in script_check.stdout:
                    Print.warn(f'  Script content:\n{script_check.stdout}')
                
                # Check script execution directly to see what happens
                test_exec = c.run(f'bash -x {script_path} 2>&1 | head -20 || true', hide=True, warn=True)
                if test_exec.stdout:
                    Print.warn(f'  Script execution test:\n{test_exec.stdout}')
                
                # Check log file
                log_check = c.run(f'test -f {remote_log} && tail -30 {remote_log} || echo "Log file not found"', hide=True, warn=True)
                if 'Log file not found' not in log_check.stdout:
                    Print.warn(f'  Last log lines:\n{log_check.stdout}')
                else:
                    Print.warn(f'  Log file {remote_log} not created')
                    # Try to check if directory exists
                    from os.path import dirname as os_dirname
                    log_dir_check = f'{repo_name}/{os_dirname(log_file)}' if os_dirname(log_file) else repo_name
                    dir_check = c.run(f'test -d {log_dir_check} && echo "Dir exists" || echo "Dir missing"', hide=True, warn=True)
                    Print.warn(f'  Log directory check: {dir_check.stdout}')
                
                # Check if command/binary exists
                binary_check = c.run(f'cd {repo_name} && which benchmark_client 2>/dev/null || which ./benchmark_client 2>/dev/null || echo "Binary not found"', hide=True, warn=True)
                if 'Binary not found' not in binary_check.stdout:
                    Print.warn(f'  Binary location: {binary_check.stdout}')
                else:
                    Print.warn(f'  ⚠ benchmark_client binary not found in PATH or current directory')
                
                # Don't raise error - let it continue, but provide detailed diagnostics
            else:
                Print.info(f'  ✓ Process {pid} is running')
                
        except Exception as e:
            if isinstance(e, BenchError):
                raise
            raise BenchError(f'Failed to start {name} on {hostname}', e)
    
    def _get_host_by_address(self, address, selected_hosts):
        """Get host info by extracting IP from address"""
        from benchmark.config import Committee
        
        # Address format: "ip:port" or "hostname:port"
        ip = Committee.ip(address)
        
        # Try to match by IP
        for host in selected_hosts:
            hostname = host['hostname']
            # Remove port if present in hostname
            if ':' in hostname:
                host_ip = hostname.split(':')[0]
            else:
                host_ip = hostname
            
            # Try direct IP match
            if host_ip == ip:
                return host
            
            # Try DNS resolution (if hostname is not an IP)
            try:
                import socket
                resolved_ip = socket.gethostbyname(host_ip)
                if resolved_ip == ip:
                    return host
            except:
                pass
        
        # Fallback: use round-robin based on address index
        # This is a simple approach - assumes addresses are in order
        if selected_hosts:
            # Extract index from address by checking committee structure
            # For now, use first available host (this should be improved)
            return selected_hosts[0]
        
        return None
    
    def _run_single(self, rate, committee, bench_parameters, node_parameters, selected_hosts, debug=False):
        """Run a single benchmark iteration (CloudLab), mirroring logic from Bench._run_single"""
        from time import sleep

        faults = bench_parameters.faults

        # 1. Kill any potentially unfinished run and delete logs (same intent as Bench._run_single)
        Print.info('Killing any existing processes and ports...')
        self.kill(hosts=selected_hosts, delete_logs=True, committee=committee, faults=faults)

        # Small delay to ensure processes are killed and database cleanup completes
        sleep(3)

        # Pre-compute workers' addresses (filtered for faults) – same as Bench._run_single
        workers_addresses = committee.workers_addresses(faults)

        # 2. Run the clients first (they will wait for the nodes to be ready)
        #    This mirrors benchmark/benchmark/remote.py::_run_single
        Print.info('Booting clients...')
        workers_total = committee.workers()
        if bench_parameters.rate_type == 'balanced':
            rate_share = ceil(rate / workers_total)
            worker_rates = [rate_share] * workers_total
        elif bench_parameters.rate_type in ('imbalanced', 'imbalance'):
            s = node_parameters.json.get('s')
            if s is None:
                raise BenchError(
                    'rate_type=imbalanced requires node parameters "s" and "v"',
                    ValueError('Missing Zipf parameters s/v')
                )
            try:
                worker_rates = ZipfAllocator(rate, workers_total, float(s)).allocate()
            except Exception as e:
                raise BenchError('Failed to allocate imbalanced client rates', e)
            Print.info(f'Client rates (Zipf, s={s}): {worker_rates}')
        else:
            raise BenchError(
                f'Unknown rate_type "{bench_parameters.rate_type}" (expected "balanced" or "imbalanced")',
                ValueError('Invalid rate_type')
            )

        worker_index = 0
        for i, addresses in enumerate(workers_addresses):
            for (id, address) in addresses:
                host_info = self._get_host_by_address(address, selected_hosts)
                if not host_info:
                    Print.warn(f'Could not find host for address {address}')
                    continue

                client_rate = worker_rates[min(worker_index, len(worker_rates) - 1)]
                cmd = CommandMaker.run_client(
                    address,
                    bench_parameters.tx_size,
                    client_rate,
                    [x for y in workers_addresses for _, x in y]
                )
                log_file = PathMaker.client_log_file(i, id)
                self._background_run(host_info, cmd, log_file)
                worker_index += 1

        # 3. Run the primaries (except the faulty ones) – same order as Bench._run_single
        Print.info('Booting primaries...')
        for i, address in enumerate(committee.primary_addresses(faults)):
            host_info = self._get_host_by_address(address, selected_hosts)
            if not host_info:
                Print.warn(f'Could not find host for address {address}')
                continue

            cmd = CommandMaker.run_primary(
                PathMaker.key_file(i),
                PathMaker.committee_file(),
                PathMaker.db_path(i),
                PathMaker.parameters_file(),
                debug=debug
            )
            log_file = PathMaker.primary_log_file(i)
            self._background_run(host_info, cmd, log_file)

        # 4. Run the workers (except the faulty ones) – same as Bench._run_single
        Print.info('Booting workers...')
        for i, addresses in enumerate(workers_addresses):
            for (id, address) in addresses:
                host_info = self._get_host_by_address(address, selected_hosts)
                if not host_info:
                    Print.warn(f'Could not find host for address {address}')
                    continue

                cmd = CommandMaker.run_worker(
                    PathMaker.key_file(i),
                    PathMaker.committee_file(),
                    PathMaker.db_path(i, id),
                    PathMaker.parameters_file(),
                    id,  # The worker's id.
                    debug=debug
                )
                log_file = PathMaker.worker_log_file(i, id)
                self._background_run(host_info, cmd, log_file)

        # 5. Wait for all transactions to be processed (progress output)
        duration = bench_parameters.duration
        Print.info(f'Running benchmark ({duration} sec)...')
        # Calculate sleep interval to ensure exact duration
        sleep_interval = duration / 20.0
        for i in range(20):
            sleep(sleep_interval)
            if (i + 1) % 5 == 0:
                Print.info(f'  Progress: {((i + 1) * 100) // 20}%')

        # 6. Kill processes but keep logs (same intent as Bench._run_single)
        self.kill(hosts=selected_hosts, delete_logs=False)
    
    def _check_stderr(self, output):
        """Check for errors in command output"""
        if isinstance(output, dict):
            for x in output.values():
                if x.stderr:
                    raise ExecutionError(x.stderr)
        else:
            if output.stderr:
                raise ExecutionError(output.stderr)
    
    def run(self, bench_parameters_dict, node_parameters_dict, debug=False):
        """Run benchmarks on CloudLab nodes
        
        Args:
            bench_parameters_dict: Benchmark parameters (may include 'trigger_attack' as bool or list)
            node_parameters_dict: Node parameters
            debug: Enable debug mode
        """
        assert isinstance(debug, bool)
        Print.heading('Starting CloudLab benchmark')
        
        # Extract trigger_attack from bench_parameters_dict (optional)
        # Support both single value and list (like rate and nodes)
        trigger_attack_raw = bench_parameters_dict.get('trigger_attack', None)
        if trigger_attack_raw is not None:
            # Convert to list if it's a single value
            if isinstance(trigger_attack_raw, list):
                trigger_attack_list = trigger_attack_raw
            else:
                trigger_attack_list = [trigger_attack_raw]
        else:
            trigger_attack_list = [None]  # Default: don't modify
        
        # Remove trigger_attack from dict before creating BenchParameters
        # (since it's not a standard parameter)
        bench_params_for_parsing = {k: v for k, v in bench_parameters_dict.items() if k != 'trigger_attack'}
        
        try:
            bench_parameters = BenchParameters(bench_params_for_parsing)
            node_parameters = NodeParameters(node_parameters_dict)
        except ConfigError as e:
            raise BenchError('Invalid nodes or bench parameters', e)
        
        # Select which hosts to use
        selected_hosts = self._select_hosts(bench_parameters)
        if not selected_hosts:
            Print.warn('There are not enough instances available')
            return
        
        # Run benchmarks for each combination of parameters
        for n in bench_parameters.nodes:
            for rate in bench_parameters.rate:
                for trigger_attack in trigger_attack_list:
                    # Update nodes (this will also modify attack.rs if trigger_attack is specified)
                    try:
                        if trigger_attack is not None:
                            Print.heading(f'\nConfiguring nodes: attack={"ENABLED" if trigger_attack else "DISABLED"}')
                        self._update(selected_hosts, bench_parameters.collocate, trigger_attack=trigger_attack)
                    except (GroupException, ExecutionError) as e:
                        e = FabricError(e) if isinstance(e, GroupException) else e
                        raise BenchError('Failed to update nodes', e)
                    
                    # Upload all configuration files
                    try:
                        committee = self._config(
                            selected_hosts, node_parameters, bench_parameters
                        )
                    except (subprocess.SubprocessError, GroupException) as e:
                        e = FabricError(e) if isinstance(e, GroupException) else e
                        raise BenchError('Failed to configure nodes', e)
                    
                    # Create a copy of committee with only n nodes
                    from copy import deepcopy
                    committee_copy = deepcopy(committee)
                    committee_copy.remove_nodes(committee.size() - n)
                    
                    # Run benchmarks for this configuration
                    for run in range(bench_parameters.runs):
                        attack_str = f", attack={'ON' if trigger_attack else 'OFF'}" if trigger_attack is not None else ""
                        Print.heading(f'\nRunning benchmark: nodes={n}, rate={rate}{attack_str}, run={run+1}/{bench_parameters.runs}')
                        
                        try:
                            # Run the actual benchmark
                            self._run_single(
                                rate, committee_copy, bench_parameters, node_parameters, selected_hosts, debug
                            )
                            
                            # Download and parse logs
                            result = self._logs(committee_copy, bench_parameters.faults, max_workers=bench_parameters.workers)
                            result.print(PathMaker.result_file(
                                bench_parameters.faults,
                                n,
                                bench_parameters.workers,
                                bench_parameters.collocate,
                                rate,
                                bench_parameters.tx_size,
                            ))
                        except (subprocess.SubprocessError, GroupException, ParseError) as e:
                            if isinstance(e, GroupException):
                                e = FabricError(e)
                            failure = BenchError('Benchmark failed', e)
                            Print.error(failure)
                            Print.warn('Leaving remote processes and logs intact for debugging.')
                            try:
                                input('Benchmark paused. Inspect the remote nodes, then press Enter to exit... ')
                            except EOFError:
                                pass
                            raise failure
        
        Print.heading('All benchmarks completed')
