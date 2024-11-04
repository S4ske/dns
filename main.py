import socket
import random
import threading
import time
from typing import Any
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")
logger = logging.getLogger(__name__)

ROOT_SERVERS = [
    "198.41.0.4",
    "199.9.14.201",
    "192.33.4.12",
    "199.7.91.13",
    "192.203.230.10",
    "192.5.5.241",
    "192.112.36.4",
    "198.97.190.53",
    "192.36.148.17",
    "192.58.128.30",
    "193.0.14.129",
    "199.7.83.42",
    "202.12.27.33",
]

cache_lock = threading.Lock()


class DnsCache:
    def __init__(self):
        self.cache: dict[str, dict[str, Any]] = {}

    def get(self, domain_name: str) -> list[str] | None:
        with cache_lock:
            entry = self.cache.get(domain_name)
        if entry:
            if time.time() < entry["expires"]:
                return entry["ips"]
            else:
                with cache_lock:
                    self.cache.pop(domain_name)
        return None

    def set(self, domain_name: str, ips: list[str], ttl: float) -> None:
        expires = time.time() + ttl
        with cache_lock:
            self.cache[domain_name] = {"ips": ips, "expires": expires}


cache = DnsCache()


def create_dns_request(domain_name: str) -> bytes:
    query_id = random.randint(0, 65535)
    header = query_id.to_bytes(2)
    header += b"\x01\x00"
    header += b"\x00\x01"
    header += b"\x00\x00"
    header += b"\x00\x00"
    header += b"\x00\x00"
    question = b"".join((len(label).to_bytes(1) + label.encode() for label in domain_name.split(".")))
    question += b"\x00" + b"\x00\x01" + b"\x00\x01"
    return header + question


def send_dns_request(request: bytes, server_ip: str, port: int = 53) -> bytes | None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2.0)
        sock.sendto(request, (server_ip, port))
        try:
            response, _ = sock.recvfrom(512)
            return response
        except socket.timeout:
            logger.warning(f"Timeout on server {server_ip}")
            return None


def parse_dns_answers(response: bytes) -> tuple[list[str], float]:
    answer_count = int.from_bytes(response[6:8])
    offset = 12 + len(response[12:].split(b"\x00", 1)[0]) + 5
    answers = []
    ttl = 0xffffffff

    for _ in range(answer_count):
        to_skip = get_length_to_skip(response, offset)
        if (response[offset + to_skip: offset + to_skip + 2] == b"\x00\x01"
                and response[offset + to_skip + 2: offset + to_skip + 4] == b"\x00\x01"):
            ttl = min(ttl, int.from_bytes(response[offset + to_skip + 4: offset + to_skip + 8]))
            rd_length = int.from_bytes(response[offset + to_skip + 8: offset + to_skip + 10])
            ip = ".".join(map(str, response[offset + to_skip + 10: offset + to_skip + 10 + rd_length]))
            answers.append(ip)
        offset += to_skip + 10 + int.from_bytes(response[offset + to_skip + 8: offset + to_skip + 10])

    return answers, ttl


def resolve_domain(domain_name: str) -> list[str] | None:
    cached_ips = cache.get(domain_name)
    if cached_ips:
        logger.info(f"Using cached result for {domain_name}: {cached_ips}")
        return cached_ips

    next_servers = ROOT_SERVERS
    while next_servers:
        for server in next_servers:
            request = create_dns_request(domain_name)
            response = send_dns_request(request, server)

            if response:
                answers, ttl = parse_dns_answers(response)

                if answers:
                    cache.set(domain_name, answers, ttl)
                    logger.info(f"Resolved {domain_name} to {answers} with TTL {ttl} via server {server}")
                    return answers

                additional_records = parse_additional(response)
                if additional_records:
                    next_servers = additional_records
                    break
        else:
            next_servers = None

    return None


def parse_additional(response: bytes) -> list[str]:
    authoritative_count = int.from_bytes(response[8:10])
    additional_count = int.from_bytes(response[10:12])
    offset = 12 + len(response[12:].split(b"\x00", 1)[0]) + 5
    for _ in range(authoritative_count):
        to_skip = get_length_to_skip(response, offset)
        offset += to_skip + 10 + int.from_bytes(response[offset + to_skip + 8: offset + to_skip + 10])
    records = []

    for _ in range(additional_count):
        to_skip = get_length_to_skip(response, offset)
        if (response[offset + to_skip: offset + to_skip + 2] == b"\x00\x01"
                and response[offset + to_skip + 2: offset + to_skip + 4] == b"\x00\x01"):
            ip = ".".join(map(str, response[offset + to_skip + 10: offset + to_skip + 10
                                                         + int.from_bytes(response[offset + 10: offset + 12])]))
            records.append(ip)
        offset += to_skip + 10 + int.from_bytes(response[offset + 10: offset + 12])

    return records


def handle_client(
        server_socket: socket.socket, message: bytes, client_address: Any
) -> None:
    domain_name = parse_dns_query_name(message)
    if not domain_name:
        server_socket.sendto(build_error_response(message, 3), client_address)
        return
    logger.info(f"Received query for {domain_name} from {client_address}")

    response_ips = resolve_domain(domain_name)
    if response_ips:
        response_message = build_response_message(message, response_ips)
        server_socket.sendto(response_message, client_address)
    else:
        server_socket.sendto(build_error_response(message, 3), client_address)
        logger.warning(f"No response found for {domain_name}")


def get_length_to_skip(message: bytes, offset: int) -> int:
    if (message[offset] & 0xc0) == 0xc0:
        return 2
    res = 1
    while message[offset] != 0:
        length = message[offset]
        offset += length + 1
        res += length + 1
    return res


def parse_dns_query_name(message: bytes) -> str | None:
    offset = 12
    domain_parts = []
    while message[offset] != 0:
        length = message[offset]
        domain_parts.append(message[offset + 1: offset + 1 + length].decode())
        offset += length + 1
    if message[offset + 1: offset + 3] != b"\x00\x01":
        return None
    return ".".join(domain_parts)


def build_response_message(query_message: bytes, response_ips: list[str]) -> bytes:
    response_id = query_message[:2]
    flags = b"\x81\x80"
    qdcount = b"\x00\x01"
    ancount = len(response_ips).to_bytes(2, byteorder='big')
    nscount = b"\x00\x00"
    arcount = b"\x00\x00"
    header = response_id + flags + qdcount + ancount + nscount + arcount

    offset = 12
    while query_message[offset] != 0:
        offset += query_message[offset] + 1
    offset += 5
    question = query_message[12:offset]

    answers = b""
    for ip in response_ips:
        answers += b"\xc0\x0c"
        answers += b"\x00\x01"
        answers += b"\x00\x01"
        answers += b"\x00\x00\x01\x2c"
        answers += b"\x00\x04"
        answers += bytes(map(int, ip.split(".")))

    return header + question + answers


def build_error_response(query_message: bytes, error_code: int) -> bytes:
    response_id = query_message[:2]
    flags = int.to_bytes(0x8180 + error_code, 2)
    qdcount = b"\x00\x01"
    ancount = b"\x00\x00"
    nscount = b"\x00\x00"
    arcount = b"\x00\x00"
    header = response_id + flags + qdcount + ancount + nscount + arcount

    offset = 12
    while query_message[offset] != 0:
        offset += query_message[offset] + 1
    offset += 5
    question = query_message[12:offset]

    return header + question


def start_dns_server(host: str = "0.0.0.0", port: int = 5353) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
        server_socket.bind((host, port))
        logger.info(f"DNS server started on {host}:{port}")
        while True:
            message, client_address = server_socket.recvfrom(512)
            threading.Thread(target=handle_client, args=(server_socket, message, client_address)).start()


if __name__ == "__main__":
    start_dns_server(port=12553)
