import asyncio
import json
import time
import uuid

import aiohttp
import requests
import yaml
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


# ============================================================
# EXCEPCIONES DE DOMINIO (reutilizadas del Informe Previo, Act. 4)
# ============================================================
class StudentNotFoundError(Exception):
    """El alumno indicado no existe en el sistema."""


class StudentAlreadyExistsError(Exception):
    """Se intenta registrar un alumno ya existente (misma MAC)."""


class CourseNotFoundError(Exception):
    """El curso indicado no existe en el sistema."""


class ServerNotFoundError(Exception):
    """El servidor indicado no existe en el sistema."""


class NotAuthorizedError(Exception):
    """El alumno no esta autorizado para acceder al servicio solicitado."""


# ============================================================
# ENTIDADES DEL DOMINIO
# ============================================================
@dataclass(frozen=True)
class Service:
    """
    Servicio expuesto por un servidor (ej. SSH TCP/22).
    frozen=True -> inmutable y hasheable (puede usarse en sets).
    """
    name:     str
    protocol: str   # "TCP" o "UDP"
    port:     int

    def __str__(self) -> str:
        return f"{self.name} ({self.protocol}/{self.port})"


@dataclass
class Student:
    """Alumno de la universidad, identificado por su MAC."""
    name: str
    mac:  str
    code: Optional[str] = None   # opcional, se asigna manualmente al crear

    def __str__(self) -> str:
        base = f"{self.name} [{self.mac}]"
        return f"{self.code} - {base}" if self.code else base


@dataclass
class Server:
    """Servidor en la red, con una lista de servicios que expone."""
    name:     str
    ip:       str
    services: List[Service] = field(default_factory=list)

    def get_service(self, service_name: str) -> Optional[Service]:
        """Devuelve el servicio por nombre, o None si no existe."""
        for svc in self.services:
            if svc.name.lower() == service_name.lower():
                return svc
        return None

    def __str__(self) -> str:
        return f"{self.name} @ {self.ip} ({len(self.services)} servicios)"


class Course:
    """
    Un curso agrupa alumnos matriculados y los servidores a los que estos
    tienen acceso, con un conjunto de servicios permitidos por servidor.
    """

    def __init__(self, name: str, code: str, state: str):
        self.name:    str                 = name
        self.code:    str                 = code
        self.state:   str                 = state   # "ACTIVE" / "INACTIVE"
        self.students: Dict[str, Student] = {}
        self.servers:  Dict[str, Server]  = {}
        self.allowed:  Dict[str, Set[str]] = {}

    # --- Gestion de alumnos ---
    def enroll(self, student: Student) -> None:
        if student.mac in self.students:
            raise StudentAlreadyExistsError(
                f"{student.name} ya matriculado en {self.code}"
            )
        self.students[student.mac] = student

    def unenroll(self, mac: str) -> Student:
        if mac not in self.students:
            raise StudentNotFoundError(
                f"MAC {mac} no matriculada en {self.code}"
            )
        return self.students.pop(mac)

    # --- Gestion de servidores y servicios permitidos ---
    def grant_access(self, server: Server, allowed_services: List[str]) -> None:
        """Registra que este curso da acceso a `server` para los servicios dados."""
        self.servers[server.name] = server
        self.allowed[server.name] = set(allowed_services)

    def allows(self, server_name: str, service_name: str) -> bool:
        """Indica si el curso permite el servicio sobre el servidor."""
        return service_name in self.allowed.get(server_name, set())

    @property
    def is_active(self) -> bool:
        return self.state.upper() == "ACTIVE"

    def __str__(self) -> str:
        return (f"[{self.code}] {self.name} ({self.state}) - "
                f"{len(self.students)} alumnos, "
                f"{len(self.servers)} servidores")


# ============================================================
# CONEXIONES Y FLOWS
# ============================================================
@dataclass
class FlowEntry:
    """
    Representa una flow entry a instalar en un switch.
    Contiene el nombre unico (clave en Floodlight) y el payload JSON
    que se enviara a /wm/staticflowentry/json.
    """
    name:    str
    switch:  str      # DPID del switch
    payload: dict     # cuerpo JSON de la flow entry

    def to_json(self) -> dict:
        """Devuelve el payload listo para POST a Floodlight."""
        return self.payload


@dataclass
class Connection:
    """
    Representa una conexion activa entre un alumno y un servidor/servicio.
    Guarda referencia a todas las flow entries instaladas, para poder
    borrarlas al eliminar la conexion.
    """
    handler:    str          # identificador unico (UUID corto)
    student:    Student
    server:     Server
    service:    Service
    flows:      List[FlowEntry] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    def __str__(self) -> str:
        return (f"[{self.handler}] {self.student.name} -> "
                f"{self.server.name}/{self.service.name} "
                f"({len(self.flows)} flows)")


# ============================================================
# LOGICA DE AUTORIZACION (Indicacion 4 del enunciado)
# ============================================================
def is_authorized(student: Student,
                  server: Server,
                  service: Service,
                  courses: Dict[str, Course]) -> Tuple[bool, str]:
    """
    Verifica si un alumno esta autorizado a usar un servicio de un servidor.

    Un alumno esta autorizado si y solo si esta matriculado en algun curso
    cumpliendo las TRES condiciones:
      (a) estado = ACTIVE
      (b) tiene al servidor Y en su lista de servidores
      (c) tiene al servicio X como parte de los "servicios permitidos" para Y

    Retorna (autorizado, razon). Si autorizado, razon identifica el curso
    que concede el permiso; si no, explica por que no.
    """
    razones_rechazo = []

    for curso in courses.values():
        # El alumno esta matriculado?
        if student.mac not in curso.students:
            continue

        # Curso activo?
        if not curso.is_active:
            razones_rechazo.append(
                f"{curso.code} tiene al alumno pero esta INACTIVE"
            )
            continue

        # Curso tiene el servidor?
        if server.name not in curso.servers:
            razones_rechazo.append(
                f"{curso.code} no incluye a {server.name}"
            )
            continue

        # Curso permite el servicio en ese servidor?
        if not curso.allows(server.name, service.name):
            allowed = sorted(curso.allowed[server.name])
            razones_rechazo.append(
                f"{curso.code} permite {allowed} en {server.name} "
                f"pero no '{service.name}'"
            )
            continue

        # Todo cumplido: autorizado
        return True, f"autorizado via curso {curso.code} ({curso.name})"

    # No encontro ningun curso que lo autorice
    if not razones_rechazo:
        return False, (f"{student.name} no esta matriculado en ningun curso "
                       f"con acceso a {server.name}")
    return False, "no autorizado: " + "; ".join(razones_rechazo)


# ============================================================
# HELPERS PARA CONSTRUIR FLOW ENTRIES
# ============================================================
def _make_flow(name:     str,
               switch:   str,
               in_port:  int,
               out_port: int,
               eth_src:  str,
               eth_dst:  str,
               eth_type: str,          # "0x0806" ARP, "0x0800" IPv4
               ip_proto: Optional[int] = None,   # 6 TCP, 17 UDP
               tp_dst:   Optional[int] = None,
               priority: int = 32768) -> FlowEntry:
    """
    Construye una flow entry para el endpoint /wm/staticflowentry/json
    de Floodlight. Devuelve un FlowEntry con nombre unico y payload JSON.
    """
    payload = {
        "switch":   switch,
        "name":     name,
        "cookie":   "0",
        "priority": str(priority),
        "in_port":  str(in_port),
        "active":   "true",
        "eth_src":  eth_src,
        "eth_dst":  eth_dst,
        "eth_type": eth_type,
        "actions":  f"output={out_port}",
    }
    if ip_proto is not None:
        payload["ip_proto"] = str(ip_proto)
    if tp_dst is not None:
        payload["tp_dst"] = str(tp_dst)
    return FlowEntry(name=name, switch=switch, payload=payload)


# ============================================================
# CARGA DE DATOS DESDE YAML
# ============================================================
def load_data(filename: str):
    """
    Carga la base de datos YAML y resuelve las referencias cruzadas
    (nombres -> objetos). Retorna tres estructuras indexadas:

      students_by_mac  : dict[mac -> Student]
      servers_by_name  : dict[server_name -> Server]
      courses_by_code  : dict[code -> Course]
    """
    with open(filename, "r") as file:
        data = yaml.safe_load(file)

    # 1. Alumnos -> indexados por MAC
    students_by_mac: Dict[str, Student] = {
        s["mac"]: Student(name=s["name"], mac=s["mac"])
        for s in data["students"]
    }

    # Indice auxiliar por nombre para resolver referencias en cursos
    students_by_name: Dict[str, Student] = {
        s.name: s for s in students_by_mac.values()
    }

    # 2. Servidores -> indexados por nombre
    servers_by_name: Dict[str, Server] = {}
    for sv in data["servers"]:
        services = [
            Service(name=s["name"], protocol=s["protocol"], port=s["port"])
            for s in sv["services"]
        ]
        servers_by_name[sv["name"]] = Server(
            name=sv["name"], ip=sv["ip"], services=services
        )

    # 3. Cursos -> resolver nombres a referencias
    courses_by_code: Dict[str, Course] = {}
    for c in data["courses"]:
        course = Course(name=c["name"], code=c["code"], state=c["state"])

        # Matricular alumnos (resolviendo nombre -> objeto)
        for student_name in c["students"]:
            if student_name not in students_by_name:
                raise ValueError(
                    f"Curso {c['code']}: alumno '{student_name}' "
                    f"no esta en la seccion 'students' del YAML"
                )
            course.enroll(students_by_name[student_name])

        # Registrar servidores con sus servicios permitidos
        for sv_ref in c["servers"]:
            if sv_ref["name"] not in servers_by_name:
                raise ValueError(
                    f"Curso {c['code']}: servidor '{sv_ref['name']}' "
                    f"no esta en la seccion 'servers' del YAML"
                )
            course.grant_access(
                server=servers_by_name[sv_ref["name"]],
                allowed_services=sv_ref["allowed_services"]
            )

        courses_by_code[c["code"]] = course

    return students_by_mac, servers_by_name, courses_by_code


# ============================================================
# CONSUMO DE LA REST API DE FLOODLIGHT
# ============================================================
def get_attachment_point(controller_ip: str, mac: str):
    """
    Consulta /wm/device/ y devuelve (switchDPID, port) donde cuelga el host
    con la MAC dada. Retorna (None, None) si no se encuentra.
    """
    endpoint = '/wm/device/'
    url = 'http://' + controller_ip + ':8080' + endpoint
    response = requests.get(url, params={'mac': mac})
    result, = response.json()
    attachment_points = result.get("attachmentPoint", [])

    if not attachment_points:
        return None, None

    attachment_point, = attachment_points
    return attachment_point["switchDPID"], attachment_point["port"]


def get_route(controller_ip: str, src_mac: str, dst_mac: str):
    """
    Devuelve la ruta de switches entre dos hosts, consultando
    /wm/topology/route/{src_dpid}/{src_port}/{dst_dpid}/{dst_port}/json.
    """
    src_sw_dpid, src_sw_port = get_attachment_point(controller_ip, src_mac)
    dst_sw_dpid, dst_sw_port = get_attachment_point(controller_ip, dst_mac)
    endpoint = (f'/wm/topology/route/{src_sw_dpid}/{src_sw_port}'
                f'/{dst_sw_dpid}/{dst_sw_port}/json')
    url = 'http://' + controller_ip + ':8080' + endpoint
    response = requests.get(url)
    return response.json()

# ============================================================
# BUILD ROUTE + INSERCION/BORRADO ASINCRONO DE FLOWS
# ============================================================
STATIC_FLOW_ENDPOINT = "/wm/staticflowpusher/json"


def _flows_for_switch(switch_dpid: str,
                      in_port:     int,
                      out_port:    int,
                      src_mac:     str,
                      dst_mac:     str,
                      src_ip:      str,
                      dst_ip:      str,
                      ip_proto:    int,
                      tp_dst:      int,
                      conn_tag:    str) -> List[FlowEntry]:
    """
    Construye los 4 flows (ARP ida/vuelta, L4 ida/vuelta) a instalar en
    un switch intermedio de la ruta. Cada flow lleva un nombre unico
    con el conn_tag para poder identificar y borrar la conexion despues.
    """
    sw_tag = switch_dpid.replace(":", "")[-6:]   # ultimos 6 hex del DPID

    flows: List[FlowEntry] = []

    # --- L4 ida (cliente -> servidor) ---
    flows.append(_make_flow(
        name=f"{conn_tag}-{sw_tag}-l4-fwd",
        switch=switch_dpid,
        in_port=in_port, out_port=out_port,
        eth_src=src_mac, eth_dst=dst_mac,
        eth_type="0x0800",
        ip_proto=ip_proto, tp_dst=tp_dst,
        priority=40000,
    ))

    # --- L4 vuelta (servidor -> cliente) ---
    #     Nota: para el reply el tp_SRC es el puerto del servicio;
    #     Floodlight no exige tp_src aqui, basta match L3+L4 inverso.
    flows.append(FlowEntry(
        name=f"{conn_tag}-{sw_tag}-l4-ret",
        switch=switch_dpid,
        payload={
            "switch":   switch_dpid,
            "name":     f"{conn_tag}-{sw_tag}-l4-ret",
            "cookie":   "0",
            "priority": "40000",
            "in_port":  str(out_port),
            "active":   "true",
            "eth_src":  dst_mac,
            "eth_dst":  src_mac,
            "eth_type": "0x0800",
            "ip_proto": str(ip_proto),
            "tp_src":   str(tp_dst),
            "actions":  f"output={in_port}",
        },
    ))

    # --- ARP ida (match solo por eth_src del cliente) ---
    flows.append(FlowEntry(
        name=f"{conn_tag}-{sw_tag}-arp-fwd",
        switch=switch_dpid,
        payload={
            "switch":   switch_dpid,
            "name":     f"{conn_tag}-{sw_tag}-arp-fwd",
            "cookie":   "0",
            "priority": "40000",
            "in_port":  str(in_port),
            "active":   "true",
            "eth_src":  src_mac,
            "eth_type": "0x0806",
            "actions":  f"output={out_port}",
        },
    ))

    # --- ARP vuelta (match solo por eth_src del servidor) ---
    flows.append(FlowEntry(
        name=f"{conn_tag}-{sw_tag}-arp-ret",
        switch=switch_dpid,
        payload={
            "switch":   switch_dpid,
            "name":     f"{conn_tag}-{sw_tag}-arp-ret",
            "cookie":   "0",
            "priority": "40000",
            "in_port":  str(out_port),
            "active":   "true",
            "eth_src":  dst_mac,
            "eth_type": "0x0806",
            "actions":  f"output={in_port}",
        },
    ))

    return flows


def _plan_flows_from_route(route_json: list,
                           src_mac: str, dst_mac: str,
                           src_ip:  str, dst_ip:  str,
                           ip_proto: int, tp_dst: int,
                           conn_tag: str) -> List[FlowEntry]:
    """
    Dada la lista cruda que devuelve /wm/topology/route/..., arma la lista
    completa de FlowEntries a instalar: 4 por cada switch intermedio.

    La ruta llega como lista de hops: [(sw,port_in), (sw,port_out), (sw,port_in), ...].
    Se consume de a pares.
    """
    flows: List[FlowEntry] = []

    # Validar que la ruta este bien formada: longitud par
    if not route_json or len(route_json) % 2 != 0:
        raise RuntimeError(
            f"Ruta vacia o malformada (len={len(route_json)}): {route_json}"
        )

    # Iterar de dos en dos: (hop_in, hop_out) en el mismo switch
    for i in range(0, len(route_json), 2):
        hop_in  = route_json[i]
        hop_out = route_json[i + 1]
        if hop_in["switch"] != hop_out["switch"]:
            raise RuntimeError(
                f"Hops consecutivos no coinciden en switch: "
                f"{hop_in['switch']} vs {hop_out['switch']}"
            )
        sw      = hop_in["switch"]
        in_port = hop_in["port"]["portNumber"]
        out_port= hop_out["port"]["portNumber"]

        flows.extend(_flows_for_switch(
            switch_dpid=sw,
            in_port=in_port, out_port=out_port,
            src_mac=src_mac, dst_mac=dst_mac,
            src_ip=src_ip,   dst_ip=dst_ip,
            ip_proto=ip_proto, tp_dst=tp_dst,
            conn_tag=conn_tag,
        ))

    return flows


async def _post_flow(session: aiohttp.ClientSession,
                     base_url: str,
                     flow:     FlowEntry) -> Tuple[str, int]:
    """POST asincrono de un flow al endpoint de Floodlight."""
    try:
        async with session.post(base_url + STATIC_FLOW_ENDPOINT,
                                json=flow.to_json()) as r:
            return (flow.name, r.status)
    except Exception as e:
        return (flow.name, -1)


async def _delete_flow(session: aiohttp.ClientSession,
                       base_url: str,
                       flow:     FlowEntry) -> Tuple[str, int]:
    """DELETE asincrono de un flow (por su 'name')."""
    try:
        payload = {"name": flow.name}
        async with session.delete(base_url + STATIC_FLOW_ENDPOINT,
                                  json=payload) as r:
            return (flow.name, r.status)
    except Exception as e:
        return (flow.name, -1)


async def _install_flows_async(flows: List[FlowEntry],
                               controller_ip: str) -> List[Tuple[str, int]]:
    """Instala todos los flows en paralelo via asyncio.gather."""
    base_url = f"http://{controller_ip}:8080"
    timeout  = aiohttp.ClientTimeout(total=10)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        tasks = [_post_flow(session, base_url, f) for f in flows]
        return await asyncio.gather(*tasks)


async def _delete_flows_async(flows: List[FlowEntry],
                              controller_ip: str) -> List[Tuple[str, int]]:
    """Borra todos los flows en paralelo."""
    base_url = f"http://{controller_ip}:8080"
    timeout  = aiohttp.ClientTimeout(total=10)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        tasks = [_delete_flow(session, base_url, f) for f in flows]
        return await asyncio.gather(*tasks)


def build_route(controller_ip: str,
                student: Student,
                server:  Server,
                service: Service,
                courses: Dict[str, Course]) -> Connection:
    """
    Orquesta la creacion de una conexion:
      1. Valida autorizacion (indicacion 4 del enunciado).
      2. Obtiene attachment points de cliente y servidor via /wm/device/.
      3. Pide la ruta a Floodlight via /wm/topology/route/.
      4. Planea los flows (ARP + L4, ida + vuelta por switch).
      5. Instala los flows en paralelo via aiohttp.
      6. Devuelve un objeto Connection con handler unico y la lista de flows.

    Lanza NotAuthorizedError o RuntimeError si algun paso falla.
    """
    # 1. Autorizacion
    ok, reason = is_authorized(student, server, service, courses)
    if not ok:
        raise NotAuthorizedError(reason)

    # 2. Attachment points
    src_dpid, src_port = get_attachment_point(controller_ip, student.mac)
    if src_dpid is None:
        raise RuntimeError(f"Floodlight no conoce al cliente {student.mac}. "
                           f"Genera trafico desde el host para que aprenda.")

    # Para el servidor necesitamos su MAC. La resolvemos tambien via /wm/device/
    # pero por IP, porque el YAML solo nos da la IP.
    server_mac = _resolve_mac_by_ip(controller_ip, server.ip)
    if server_mac is None:
        raise RuntimeError(f"Floodlight no conoce a {server.name} ({server.ip}). "
                           f"Genera trafico desde el servidor para que aprenda.")

    dst_dpid, dst_port = get_attachment_point(controller_ip, server_mac)
    if dst_dpid is None:
        raise RuntimeError(f"Floodlight tiene a {server.ip} pero sin attachment point.")

    # 3. Ruta
    endpoint = (f"/wm/topology/route/{src_dpid}/{src_port}"
                f"/{dst_dpid}/{dst_port}/json")
    r = requests.get(f"http://{controller_ip}:8080" + endpoint, timeout=5)
    route = r.json()
    if not route:
        raise RuntimeError(f"Floodlight no pudo calcular ruta: {route}")

    # 4. Plan de flows
    ip_proto = 6 if service.protocol.upper() == "TCP" else 17
    handler  = uuid.uuid4().hex[:8]           # 8 hex, suficientemente unico
    conn_tag = f"c-{handler}"
    flows = _plan_flows_from_route(
        route_json=route,
        src_mac=student.mac, dst_mac=server_mac,
        src_ip="0.0.0.0",   dst_ip="0.0.0.0",  # no se matchean L3 por IP aqui
        ip_proto=ip_proto, tp_dst=service.port,
        conn_tag=conn_tag,
    )

    # 5. Instalar en paralelo
    results = asyncio.run(_install_flows_async(flows, controller_ip))
    fallidos = [(n, s) for (n, s) in results if s != 200]
    if fallidos:
        # Rollback de los que si se instalaron
        asyncio.run(_delete_flows_async(flows, controller_ip))
        raise RuntimeError(f"Fallo la instalacion de flows: {fallidos}")

    # 6. Devolver conexion
    return Connection(
        handler=handler, student=student,
        server=server, service=service,
        flows=flows,
    )


def delete_route(controller_ip: str, conn: Connection) -> List[Tuple[str, int]]:
    """
    Borra todos los flows de una conexion. Devuelve la lista de resultados
    (nombre, status_http) por cada flow borrado.
    """
    return asyncio.run(_delete_flows_async(conn.flows, controller_ip))


def _resolve_mac_by_ip(controller_ip: str, ip: str) -> Optional[str]:
    """
    Consulta /wm/device/?ipv4=<ip> para resolver la MAC asociada.
    Devuelve None si Floodlight aun no conoce al host.
    """
    url = f"http://{controller_ip}:8080/wm/device/"
    r   = requests.get(url, params={"ipv4": ip}, timeout=5)
    devices = r.json()
    for d in devices:
        macs = d.get("mac", [])
        if macs:
            return macs[0]
    return None

# ============================================================
# UTILIDADES DE PRESENTACION
# ============================================================
def _separator(title: str = "", width: int = 60) -> None:
    """Imprime un separador con titulo centrado."""
    if title:
        print("\n" + f" {title} ".center(width, "="))
    else:
        print("=" * width)


def _prompt(msg: str) -> str:
    """Entrada de usuario con prompt limpio."""
    return input(f"\n{msg} ").strip()


def _pause() -> None:
    input("\nPresione ENTER para continuar...")


# ============================================================
# SUBMENU: CURSOS
# ============================================================
def menu_cursos(state: dict) -> None:
    courses  = state["courses"]
    students = state["students"]
    while True:
        _separator("CURSOS")
        print("  1. Crear")
        print("  2. Listar")
        print("  3. Mostrar detalles")
        print("  4. Actualizar")
        print("  5. Gestionar alumnos")
        print("  6. Borrar")
        print("  7. Volver")
        op = _prompt("Opcion:")

        if op == "1":
            code  = _prompt("Codigo del curso (ej. HGW104):").upper()
            if code in courses:
                print(f"[ERROR] Ya existe un curso con codigo {code}")
                _pause()
                continue
            name  = _prompt("Nombre del curso:")
            state_ = _prompt("Estado (ACTIVE / INACTIVE):").upper() or "ACTIVE"
            if state_ not in ("ACTIVE", "INACTIVE"):
                print("[ERROR] Estado invalido")
                _pause()
                continue
            new_course = Course(name=name, code=code, state=state_)
            courses[code] = new_course
            print(f"[OK] Curso creado: {new_course}")

        elif op == "2":
            _separator("Cursos existentes")
            for c in courses.values():
                print(f"  {c}")

        elif op == "3":
            code = _prompt("Codigo del curso:").upper()
            curso = courses.get(code)
            if not curso:
                print(f"[ERROR] No existe el curso {code}")
            else:
                _separator(f"Detalle del curso {code}")
                print(f"  Nombre : {curso.name}")
                print(f"  Codigo : {curso.code}")
                print(f"  Estado : {curso.state}")
                print(f"  Alumnos matriculados ({len(curso.students)}):")
                for st in curso.students.values():
                    print(f"    - {st}")
                print(f"  Servidores accesibles ({len(curso.servers)}):")
                for sv_name, sv in curso.servers.items():
                    allowed = sorted(curso.allowed[sv_name])
                    print(f"    - {sv_name} @ {sv.ip} -> servicios permitidos: {allowed}")

        elif op == "4":
            code = _prompt("Codigo del curso a actualizar:").upper()
            curso = courses.get(code)
            if not curso:
                print(f"[ERROR] No existe el curso {code}")
                _pause()
                continue
            print(f"[Actual] Nombre={curso.name}, Estado={curso.state}")
            new_name  = _prompt("Nuevo nombre (ENTER para dejar igual):") or curso.name
            new_state = (_prompt("Nuevo estado ACTIVE/INACTIVE (ENTER para dejar igual):")
                         .upper() or curso.state)
            if new_state not in ("ACTIVE", "INACTIVE"):
                print("[ERROR] Estado invalido")
                _pause()
                continue
            curso.name  = new_name
            curso.state = new_state
            print(f"[OK] Curso actualizado: {curso}")

        elif op == "5":
            code = _prompt("Codigo del curso:").upper()
            curso = courses.get(code)
            if not curso:
                print(f"[ERROR] No existe el curso {code}")
                _pause()
                continue
            while True:
                _separator(f"Gestionar alumnos de {code}")
                print(f"  Alumnos matriculados ({len(curso.students)}):")
                for st in curso.students.values():
                    print(f"    - {st}")
                print("\n  1. Agregar alumno")
                print("  2. Remover alumno")
                print("  3. Volver")
                sub = _prompt("Opcion:")

                if sub == "1":
                    mac = _prompt("MAC del alumno a matricular:")
                    st  = students.get(mac)
                    if not st:
                        print(f"[ERROR] No existe alumno con MAC {mac}. "
                              f"Crealo primero desde el menu Alumnos.")
                    else:
                        try:
                            curso.enroll(st)
                            print(f"[OK] {st.name} matriculado en {code}")
                        except StudentAlreadyExistsError as e:
                            print(f"[ERROR] {e}")
                elif sub == "2":
                    mac = _prompt("MAC del alumno a remover:")
                    try:
                        removed = curso.unenroll(mac)
                        print(f"[OK] {removed.name} removido de {code}")
                    except StudentNotFoundError as e:
                        print(f"[ERROR] {e}")
                elif sub == "3":
                    break
                else:
                    print("[ERROR] Opcion invalida")
                _pause()

        elif op == "6":
            code = _prompt("Codigo del curso a borrar:").upper()
            if code not in courses:
                print(f"[ERROR] No existe el curso {code}")
            else:
                removed = courses.pop(code)
                print(f"[OK] Curso borrado: {removed.name}")

        elif op == "7":
            return
        else:
            print("[ERROR] Opcion invalida")
        _pause()


# ============================================================
# SUBMENU: ALUMNOS
# ============================================================
def menu_alumnos(state: dict) -> None:
    students = state["students"]
    courses  = state["courses"]
    while True:
        _separator("ALUMNOS")
        print("  1. Crear")
        print("  2. Listar")
        print("  3. Mostrar detalles")
        print("  4. Actualizar")
        print("  5. Borrar")
        print("  6. Volver")
        op = _prompt("Opcion:")

        if op == "1":
            name = _prompt("Nombre completo:")
            if not name:
                print("[ERROR] El nombre no puede estar vacio")
                _pause()
                continue
            mac = _prompt("Direccion MAC:")
            if not mac:
                print("[ERROR] La MAC no puede estar vacia")
                _pause()
                continue
            if mac in students:
                print(f"[ERROR] Ya existe un alumno con MAC {mac}: {students[mac].name}")
                _pause()
                continue
            code = _prompt("Codigo PUCP (ENTER para omitir):") or None

            new_student = Student(name=name, mac=mac, code=code)
            students[mac] = new_student
            print(f"[OK] Alumno creado: {new_student}")

        elif op == "2":
            _separator("Alumnos registrados")
            filtro = _prompt("Filtrar por codigo de curso (ENTER para listar todos):").upper()
            if filtro:
                curso = courses.get(filtro)
                if not curso:
                    print(f"[ERROR] No existe el curso {filtro}")
                    _pause()
                    continue
                _separator(f"Alumnos del curso {filtro}")
                if not curso.students:
                    print("  (sin alumnos matriculados)")
                for st in curso.students.values():
                    print(f"  - {st}")
            else:
                for st in students.values():
                    print(f"  - {st}")

        elif op == "3":
            mac = _prompt("MAC del alumno:")
            st = students.get(mac)
            if not st:
                print(f"[ERROR] No existe alumno con MAC {mac}")
            else:
                _separator(f"Detalle de {st.name}")
                print(f"  Nombre : {st.name}")
                print(f"  MAC    : {st.mac}")
                print(f"  Codigo : {st.code if st.code else '(no asignado)'}")
                print(f"  Matriculado en:")
                matriculas = [c for c in courses.values() if mac in c.students]
                if not matriculas:
                    print("    (ningun curso)")
                for c in matriculas:
                    print(f"    - [{c.code}] {c.name} ({c.state})")

        elif op == "4":
            mac = _prompt("MAC del alumno a actualizar:")
            st = students.get(mac)
            if not st:
                print(f"[ERROR] No existe alumno con MAC {mac}")
                _pause()
                continue
            print(f"[Actual] Nombre={st.name}, Codigo={st.code}")
            new_name = _prompt("Nuevo nombre (ENTER para dejar igual):") or st.name
            new_code = _prompt("Nuevo codigo (ENTER para dejar igual):") or st.code
            st.name = new_name
            st.code = new_code
            print(f"[OK] Alumno actualizado: {st}")

        elif op == "5":
            mac = _prompt("MAC del alumno a borrar:")
            if mac not in students:
                print(f"[ERROR] No existe alumno con MAC {mac}")
                _pause()
                continue
            for c in courses.values():
                if mac in c.students:
                    c.unenroll(mac)
            removed = students.pop(mac)
            print(f"[OK] Alumno borrado: {removed.name}")

        elif op == "6":
            return
        else:
            print("[ERROR] Opcion invalida")
        _pause()


# ============================================================
# SUBMENU: SERVIDORES
# ============================================================
def menu_servidores(state: dict) -> None:
    servers = state["servers"]
    courses = state["courses"]
    while True:
        _separator("SERVIDORES Y SERVICIOS")
        print("  1. Crear")
        print("  2. Listar")
        print("  3. Mostrar servicios")
        print("  4. Actualizar")
        print("  5. Borrar")
        print("  6. Buscar cursos con acceso a un servicio")
        print("  7. Volver")
        op = _prompt("Opcion:")

        if op == "1":
            print("[TODO] Crear servidor")
        elif op == "2":
            _separator("Servidores registrados")
            for sv in servers.values():
                print(f"  - {sv.name:<12} IP: {sv.ip}")
        elif op == "3":
            name = _prompt("Nombre del servidor (ej. Server 3):")
            sv = servers.get(name)
            if not sv:
                print(f"[ERROR] No existe el servidor '{name}'")
            else:
                _separator(f"Servicios de {sv.name}")
                print(f"  IP: {sv.ip}")
                print(f"  Servicios expuestos ({len(sv.services)}):")
                for svc in sv.services:
                    print(f"    - {svc}")
                print(f"\n  Cursos que acceden a este servidor:")
                found = False
                for c in courses.values():
                    if sv.name in c.servers:
                        allowed = sorted(c.allowed[sv.name])
                        print(f"    - [{c.code}] {c.name} ({c.state}) -> {allowed}")
                        found = True
                if not found:
                    print("    (ninguno)")
        elif op == "4":
            print("[TODO] Actualizar servidor")
        elif op == "5":
            print("[TODO] Borrar servidor")
        elif op == "6":
            name = _prompt("Nombre del servidor (ej. Server 3):")
            sv = servers.get(name)
            if not sv:
                print(f"[ERROR] No existe el servidor '{name}'")
                _pause()
                continue
            svc_name = _prompt(f"Nombre del servicio en {sv.name} (ej. ssh):").lower()
            if not sv.get_service(svc_name):
                print(f"[ERROR] El servidor '{sv.name}' no expone el servicio '{svc_name}'")
                _pause()
                continue
            _separator(f"Cursos con acceso a {svc_name} en {sv.name}")
            matches = [c for c in courses.values() if c.allows(sv.name, svc_name)]
            if not matches:
                print("  (ningun curso tiene este acceso)")
            for c in matches:
                marca = "ACTIVO" if c.is_active else "INACTIVO - no efectivo"
                print(f"  - [{c.code}] {c.name} ({c.state}) [{marca}]")
        elif op == "7":
            return
        else:
            print("[ERROR] Opcion invalida")
        _pause()


# ============================================================
# SUBMENU: POLITICAS
# ============================================================
def menu_politicas(state: dict) -> None:
    _separator("POLITICAS")
    print("  [Vista de politicas de autorizacion por curso]")
    courses = state["courses"]
    for c in courses.values():
        print(f"\n  [{c.code}] {c.name} ({c.state})")
        for sv_name, allowed in c.allowed.items():
            print(f"    {sv_name:<12} -> {sorted(allowed)}")
    _pause()


# ============================================================
# SUBMENU: CONEXIONES
# ============================================================
def menu_conexiones(state: dict) -> None:
    students  = state["students"]
    servers   = state["servers"]
    courses   = state["courses"]
    ctrl_ip   = state["controller_ip"]
    conns     = state.setdefault("connections", {})   # handler -> Connection

    while True:
        _separator("CONEXIONES")
        print(f"  Activas: {len(conns)}")
        print("  1. Crear")
        print("  2. Listar")
        print("  3. Mostrar detalles")
        print("  4. Borrar")
        print("  5. Volver")
        op = _prompt("Opcion:")

        # ---------- CREAR ----------
        if op == "1":
            mac = _prompt("MAC del alumno:")
            st  = students.get(mac)
            if not st:
                print(f"[ERROR] No existe alumno con MAC {mac}")
                _pause(); continue

            sv_name = _prompt("Nombre del servidor (ej. Server 3):")
            sv      = servers.get(sv_name)
            if not sv:
                print(f"[ERROR] No existe el servidor '{sv_name}'")
                _pause(); continue

            svc_name = _prompt(f"Servicio en {sv.name} (ej. ssh):").lower()
            svc      = sv.get_service(svc_name)
            if not svc:
                print(f"[ERROR] {sv.name} no expone '{svc_name}'")
                _pause(); continue

            print(f"\n[*] Validando autorizacion y construyendo ruta ...")
            try:
                conn = build_route(ctrl_ip, st, sv, svc, courses)
            except NotAuthorizedError as e:
                print(f"[ACCESO DENEGADO] {e}")
                _pause(); continue
            except RuntimeError as e:
                print(f"[ERROR] {e}")
                _pause(); continue
            except Exception as e:
                print(f"[ERROR inesperado] {type(e).__name__}: {e}")
                _pause(); continue

            conns[conn.handler] = conn
            print(f"[OK] Conexion creada con handler = {conn.handler}")
            print(f"     {conn}")
            print(f"     Flows instalados: {len(conn.flows)}")

        # ---------- LISTAR ----------
        elif op == "2":
            _separator("Conexiones activas")
            if not conns:
                print("  (ninguna)")
            for c in conns.values():
                print(f"  - {c}")

        # ---------- MOSTRAR DETALLES ----------
        elif op == "3":
            handler = _prompt("Handler de la conexion:")
            c = conns.get(handler)
            if not c:
                print(f"[ERROR] No existe conexion con handler '{handler}'")
            else:
                _separator(f"Detalle de conexion {handler}")
                print(f"  Alumno    : {c.student}")
                print(f"  Servidor  : {c.server}")
                print(f"  Servicio  : {c.service}")
                print(f"  Flows ({len(c.flows)}):")
                # Resumen por switch
                por_sw: Dict[str, List[str]] = {}
                for f in c.flows:
                    por_sw.setdefault(f.switch, []).append(f.name)
                for sw, nombres in por_sw.items():
                    print(f"    - {sw}  ({len(nombres)} flows)")
                    for n in nombres:
                        print(f"        . {n}")

        # ---------- BORRAR ----------
        elif op == "4":
            handler = _prompt("Handler de la conexion a borrar:")
            c = conns.get(handler)
            if not c:
                print(f"[ERROR] No existe conexion con handler '{handler}'")
                _pause(); continue
            print(f"[*] Borrando {len(c.flows)} flows ...")
            try:
                results = delete_route(ctrl_ip, c)
                fallidos = [(n, s) for (n, s) in results if s != 200]
                if fallidos:
                    print(f"[AVISO] Algunos flows no respondieron 200: {fallidos}")
                else:
                    print(f"[OK] Todos los flows ({len(results)}) borrados correctamente")
                del conns[handler]
            except Exception as e:
                print(f"[ERROR] {e}")

        elif op == "5":
            return
        else:
            print("[ERROR] Opcion invalida")
        _pause()

# ============================================================
# IMPORTAR / EXPORTAR
# ============================================================
def importar(state: dict) -> None:
    filename = _prompt("Nombre del archivo YAML a importar:")
    try:
        students, servers, courses = load_data(filename)
        state["students"] = students
        state["servers"]  = servers
        state["courses"]  = courses
        print(f"[OK] Importados: {len(students)} alumnos, "
              f"{len(servers)} servidores, {len(courses)} cursos")
    except FileNotFoundError:
        print(f"[ERROR] Archivo '{filename}' no encontrado")
    except Exception as e:
        print(f"[ERROR] {e}")
    _pause()


def exportar(state: dict) -> None:
    print("[TODO] Exportar estado a YAML")
    _pause()


# ============================================================
# MENU PRINCIPAL
# ============================================================
def menu():
    try:
        students, servers, courses = load_data("database.yaml")
    except FileNotFoundError:
        print("[ERROR] No se encontro 'database.yaml' en el directorio actual")
        return

    state = {
        "students": students,
        "servers":  servers,
        "courses":  courses,
        "controller_ip": "localhost",
    }

    while True:
        _separator("APLICACION SDN - TEL354 LAB 4")
        print(f"  Datos cargados: {len(state['students'])} alumnos, "
              f"{len(state['servers'])} servidores, {len(state['courses'])} cursos")
        print()
        print("  1. Importar")
        print("  2. Exportar")
        print("  3. Cursos")
        print("  4. Alumnos")
        print("  5. Servidores")
        print("  6. Politicas")
        print("  7. Conexiones")
        print("  8. Salir")
        op = _prompt("Opcion:")

        if   op == "1": importar(state)
        elif op == "2": exportar(state)
        elif op == "3": menu_cursos(state)
        elif op == "4": menu_alumnos(state)
        elif op == "5": menu_servidores(state)
        elif op == "6": menu_politicas(state)
        elif op == "7": menu_conexiones(state)
        elif op == "8":
            print("\nSaliendo...")
            return
        else:
            print("[ERROR] Opcion invalida")


# ============================================================
# ENTRYPOINT
# ============================================================
def main():
    menu()


if __name__ == "__main__":
    main()