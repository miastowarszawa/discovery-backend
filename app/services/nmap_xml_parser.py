import xml.etree.ElementTree as ET

from app.schemas.nmap_import import (
    NmapHost,
    NmapParseResult,
    NmapParseSummary,
    NmapPort,
    NmapScriptResult,
    NmapServiceInfo,
)


def _parse_script(node: ET.Element) -> NmapScriptResult:
    return NmapScriptResult(
        script_id=node.attrib.get('id', ''),
        output=node.attrib.get('output'),
    )


def _parse_service(node: ET.Element | None) -> NmapServiceInfo | None:
    if node is None:
        return None

    cpes = [
        cpe.text.strip()
        for cpe in node.findall('cpe')
        if cpe.text and cpe.text.strip()
    ]

    return NmapServiceInfo(
        name=node.attrib.get('name'),
        product=node.attrib.get('product'),
        version=node.attrib.get('version'),
        extrainfo=node.attrib.get('extrainfo'),
        method=node.attrib.get('method'),
        conf=node.attrib.get('conf'),
        cpes=cpes,
    )


def _parse_port(node: ET.Element) -> NmapPort:
    state_node = node.find('state')
    service_node = node.find('service')
    script_nodes = node.findall('script')

    return NmapPort(
        port=int(node.attrib.get('portid', '0')),
        protocol=node.attrib.get('protocol', 'tcp'),
        state=state_node.attrib.get('state') if state_node is not None else None,
        reason=state_node.attrib.get('reason') if state_node is not None else None,
        service=_parse_service(service_node),
        scripts=[_parse_script(script) for script in script_nodes],
    )


def _parse_host(node: ET.Element) -> NmapHost:
    status_node = node.find('status')

    addresses = []
    hostnames = []

    for address in node.findall('address'):
        addr = address.attrib.get('addr')
        if addr:
            addresses.append(addr)

    hostnames_node = node.find('hostnames')
    if hostnames_node is not None:
        for hostname in hostnames_node.findall('hostname'):
            name = hostname.attrib.get('name')
            if name:
                hostnames.append(name)

    ports = []
    ports_node = node.find('ports')
    if ports_node is not None:
        for port in ports_node.findall('port'):
            ports.append(_parse_port(port))

    scripts = [
        _parse_script(script)
        for script in node.findall('hostscript/script')
    ]

    return NmapHost(
        addresses=list(dict.fromkeys(addresses)),
        hostnames=list(dict.fromkeys(hostnames)),
        status=status_node.attrib.get('state') if status_node is not None else None,
        ports=ports,
        scripts=scripts,
    )


def parse_nmap_xml(xml_text: str) -> NmapParseResult:
    root = ET.fromstring(xml_text)

    hosts = [_parse_host(host) for host in root.findall('host')]
    up_hosts = [host for host in hosts if host.status == 'up']

    total_ports = sum(len(host.ports) for host in hosts)
    total_scripts = sum(
        len(host.scripts) + sum(len(port.scripts) for port in host.ports)
        for host in hosts
    )

    return NmapParseResult(
        scanner=root.attrib.get('scanner'),
        args=root.attrib.get('args'),
        started=root.attrib.get('startstr'),
        hosts=hosts,
        summary=NmapParseSummary(
            total_hosts=len(hosts),
            up_hosts=len(up_hosts),
            total_ports=total_ports,
            total_scripts=total_scripts,
        ),
    )
