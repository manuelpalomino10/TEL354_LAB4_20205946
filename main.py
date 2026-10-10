import yaml
import json
import requests
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


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
# Stubs del enunciado (los implementaremos en fases siguientes)
# ============================================================
def get_attachment_point(controller_ip, mac):
    endpoint = '/wm/device/'
    url = 'http://' + controller_ip + ':8080' + endpoint
    response = requests.get(url, params={'mac': mac})
    result, = response.json()
    attachment_points = result.get("attachmentPoint", [])

    if not attachment_points:
        return None, None

    attachment_point, = attachment_points
    return attachment_point["switchDPID"], attachment_point["port"]


def get_route(controller_ip, src_mac, dst_mac):
    src_sw_dpid, src_sw_port = get_attachment_point(controller_ip, src_mac)
    dst_sw_dpid, dst_sw_port = get_attachment_point(controller_ip, dst_mac)
    endpoint = f'/wm/topology/route/{src_sw_dpid}/{src_sw_port}/{dst_sw_dpid}/{dst_sw_port}/json'
    url = 'http://' + controller_ip + ':8080' + endpoint
    response = requests.get(url)
    return response.json()


def menu():
    # TODO: implementar en Fase 2
    print()


def build_route():
    # TODO: implementar en Fase 5
    print()


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
            # --- Crear curso ---
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
            # --- Actualizar curso ---
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
            # --- Gestionar alumnos del curso ---
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
            # --- Borrar curso ---
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
            # --- Crear alumno ---
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
            # --- Actualizar alumno ---
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
            # --- Borrar alumno ---
            mac = _prompt("MAC del alumno a borrar:")
            if mac not in students:
                print(f"[ERROR] No existe alumno con MAC {mac}")
                _pause()
                continue
            # Desmatricular de todos los cursos primero
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
            print("[TODO] Crear servidor (Fase 3)")
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
            print("[TODO] Actualizar servidor (Fase 3)")
        elif op == "5":
            print("[TODO] Borrar servidor (Fase 3)")
        elif op == "6":
            # Filtro cursos por acceso a un servicio especifico sobre un servidor
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
# SUBMENU: POLITICAS (placeholder - no obligatorio segun rubrica)
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
# SUBMENU: CONEXIONES (stub - se implementa en Fase 6)
# ============================================================
def menu_conexiones(state: dict) -> None:
    while True:
        _separator("CONEXIONES")
        print("  1. Crear")
        print("  2. Listar")
        print("  3. Mostrar detalles")
        print("  4. Recalcular")
        print("  5. Actualizar")
        print("  6. Borrar")
        print("  7. Volver")
        op = _prompt("Opcion:")

        if op == "7":
            return
        print(f"[TODO] Opcion {op} de Conexiones (Fase 6: build_route + flows)")
        _pause()


# ============================================================
# IMPORTAR / EXPORTAR (stub - Fase 7)
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
    print("[TODO] Exportar estado a YAML (Fase 7)")
    _pause()


# ============================================================
# MENU PRINCIPAL
# ============================================================
def menu():
    # Carga inicial
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
# MAIN (temporal: solo verificacion de carga - Fase 1)
# ============================================================
def main():
   menu()


if __name__ == "__main__":
    main()