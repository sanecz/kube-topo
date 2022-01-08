import argparse
import hashlib
import ipaddress
import logging
import networkx as nx

from functools import reduce, partial, partialmethod
from kubernetes import client, config
from kubernetes.stream import stream
from parse import parse
from pyvis.network import Network

logger = logging.getLogger(__name__)

# https://www.kernel.org/doc/Documentation/networking/proc_net_tcp.txt
NET_FORMAT = (
    "{id:>4d}: {src:x}:{srcp:04x} {rem:x}:{remp:04x} {state:02x} "
    "{tx_queue:08x}:{rx_queue:08x} {timer_active:02x}:{timer_expires:08x} "
    "{retransmit:08x} {uid:>5d} {probes:>8d} {inode:d} {refcount:d} {pointer}"
)

TCP_FORMAT = NET_FORMAT + " {rto:d} {ato:d} {qopm:d} {cwindow:d} {slowstart:d}"
UDP_FORMAT = NET_FORMAT + " {drops:d}"


def _swap_endianess(integer):
    return int.from_bytes(integer.to_bytes(4, byteorder='little'), byteorder='big', signed=False)

def _parse_netstat(output):
    connections = {}

    for line in output.split("\n"):
        line = line.strip()
        parsed_line = None
        # fallback to NET_FORMAT when everything fails ?
        for fmt_type in [TCP_FORMAT, UDP_FORMAT, NET_FORMAT]:
            try:
                parsed_line = parse(fmt_type, line).named
                break
            except AttributeError:
                continue
        else:
            logger.warning(f"Line: {line} not parsed")
            continue

        ip_src = ipaddress.ip_address(_swap_endianess(parsed_line["src"]))
        ip_rem = ipaddress.ip_address(_swap_endianess(parsed_line["rem"]))

        # FIXME: state listen
        if str(ip_rem) == '127.0.0.1' or str(ip_src) == '127.0.0.1' or str(ip_src) == '0.0.0.0' or str(ip_rem) == '0.0.0.0':
            logger.info(f"Ignoring {ip_src} :: {ip_rem} , local address or listen")
            continue

        # FIXME: allowlist
        if not ip_rem.is_private:
            logger.debug(f"Ignoring {ip_rem} because it's not a private ip")
            continue

        # sysctl net.ipv4.ip_local_port_range
        # FIXME: cfg
        if 32768 < parsed_line['srcp'] < 60999:
            # we are connected to something possibly
            pass #plustard
        else:
            connections.setdefault(f"{parsed_line['srcp']}", []).append(str(ip_rem))

    connections = {k: list(set(v)) for k, v in connections.items()}

    return connections


def _get_netstats(kube_api, namespace, pod):
    logger.info(f"Retrieving netstats for {namespace}/{pod.metadata.name}")

    connections = {}
    for container in pod.spec.containers:
        container = container.name
        logger.info(f"Testing: {namespace}/{pod.metadata.name}/{container}")
        # FIXME: support ipv6 later
        exec_netstat_command = [
            'cat',
            '/proc/net/tcp',
#            '/proc/net/tcp6',
            '/proc/net/udp',
#            '/proc/net/udp6'
        ]
        try:
            resp = stream(
                kube_api.connect_get_namespaced_pod_exec,
                name=pod.metadata.name, namespace=namespace, container=container,
                command=exec_netstat_command,
                stderr=True, stdin=False,
                stdout=True, tty=False
            )
        except Exception as e:
            logger.error(f"Cannot connect to {namespace}/{pod.metadata.name}/{container}: '{e}'")
        else:
            logger.debug(_parse_netstat(resp))
            connections |= _parse_netstat(resp)


        logger.debug(connections)

    return connections


def get_netstats(kube_api, pod_list):
    for group_name, pods in pod_list.copy().items():
        for i, pod in enumerate(pods["pods"]):
            pod_list[group_name].setdefault("connections", {})
            pod_list[group_name]["connections"] |= _get_netstats(kube_api, pods["namespace"], pod)

    return pod_list

def get_pods(kube_api, namespaces, all_ns):
     # kubectl get pods -n netbox -o name

    pods = {}

    for elem in all_ns.items:
        if elem.metadata.namespace not in namespaces:
            continue
        short_pod_name = elem.metadata.name.split("-")
        # FIXME: find a better way to get base name of a pod
        short_pod_name = "-".join(
            short_pod_name[:-2] if len(short_pod_name[-1]) == 5 and len(short_pod_name[-2]) >= 9 else short_pod_name
        )
        if not elem.status.container_statuses[0].started:
            logger.info(f"IGN: {elem.metadata.name}, status not started")
            continue
        
        pods.setdefault(short_pod_name, {
            "namespace": elem.metadata.namespace,
            "pods": [],
            "ips": []
        })

        logger.debug(f"{short_pod_name} {elem.metadata.name}")
        pods[short_pod_name]["pods"].append(elem)
        pods[short_pod_name]["ips"].append(elem.status.pod_ip)
    
    return get_netstats(kube_api, pods)


def get_pod_by_ip(pods_list, ip, all_ns):
    for group_name, pods in pods_list.items():
        if ip in pods["ips"]:
            return f'{pods["namespace"]}/{group_name}'
    for item in all_ns.items:
        if ip == item.status.pod_ip:
            short_pod_name = item.metadata.name.split("-")
            # FIXME: find a better way to get base name of a pod
            short_pod_name = "-".join(
                short_pod_name[:-2] if len(short_pod_name[-1]) == 5 and len(short_pod_name[-2]) >= 9 else short_pod_name
            )            
            return f'{item.metadata.namespace}/{short_pod_name}'

def draw_pods(namespaces):
    config.load_kube_config()
    kube_api = client.CoreV1Api()
    all_ns = kube_api.list_pod_for_all_namespaces(watch=False)
    pods_list = get_pods(kube_api, namespaces, all_ns)

    net = Network('768px', '1366px', directed=True)
    # create all nodes firsts
    # TODO: extend class to put more informations inside each nodes
    for group_name, pods in pods_list.items():
        color = hashlib.md5(bytes(pods["namespace"].encode("utf8"))).hexdigest()[:6]
        net.add_node(f"{pods['namespace']}/{group_name}", title=",".join(pods["ips"]), color=f"#{color}")

    # FIXME: ignore stuff from kube-system or maybe ingress too
    # configurable if possible
    for group_name, pods in pods_list.items():
        for port, ips in pods["connections"].items():
            for ip in ips:
                dest_pod = get_pod_by_ip(pods_list, ip, all_ns)
                try:
                    net.get_node(dest_pod)
                except: # FIXME: bad
                    if not dest_pod:
                        dest_pod = ip
                    if dest_pod.split("/")[0] == pods["namespace"]:
                        color = hashlib.md5(bytes(pods["namespace"].encode("utf8"))).hexdigest()[:6]
                    else:
                        color = hashlib.md5(bytes(dest_pod.split("/")[0].encode("utf8"))).hexdigest()[:6]
                    net.add_node(dest_pod, title=ip, color=f"#{color}")
                    net.add_edge(
                        dest_pod, f"{pods['namespace']}/{group_name}",
                        label=f":{port}", arrowStrikethrough=True
                    )
                else:
                    net.add_edge(dest_pod, f"{pods['namespace']}/{group_name}",
                                 label=f":{port}", arrowStrikethrough=True)

    net.show("test.html")


def main():
    """
    Main program
    """
    global logger

    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--log", dest="verbose", choices=['TRACE', 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], help="increase verbosity")
    parser.add_argument("-n", "--namespaces", help="list of namespaces to topo", nargs="+", action="append")
    args = parser.parse_args()

    namespaces = reduce(
        lambda a, b: a + b if isinstance(a, list) else [a] + b,
        args.namespaces
    )

    logging.addLevelName(logging.INFO, "\033[1;32m%s\033[1;0m" % logging.getLevelName(logging.INFO))
    logging.addLevelName(logging.DEBUG, "\033[1;34m%s\033[1;0m" % logging.getLevelName(logging.DEBUG))
    logging.addLevelName(logging.WARNING, "\033[1;31m%s\033[1;0m" % logging.getLevelName(logging.WARNING))
    logging.addLevelName(logging.ERROR, "\033[1;41m%s\033[1;0m" % logging.getLevelName(logging.ERROR))

    if args.verbose:
        logging.basicConfig(level=logging.getLevelName(args.verbose))
    else:
        logging.basicConfig(level=logging.WARNING)

    draw_pods(namespaces)


if __name__ == "__main__":
    main()
