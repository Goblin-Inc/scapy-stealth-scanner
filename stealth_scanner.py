import sys
import logging
import time
import random

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, TCP, sr1, send

class AdvancedStealthScanner:
    def __init__(self, target_ip, spoofed_ip=None):
        self.target_ip = target_ip
        self.spoofed_ip = spoofed_ip # Если None, отправится с твоего реального IP

    def xmas_scan(self, port):
        """ Скрытый Xmas-сканер с поддержкой подмены IP-адреса """
        # Формируем IP слой. Если задан фейковый IP, подставляем его в src (source)
        if self.spoofed_ip:
            ip_layer = IP(src=self.spoofed_ip, dst=self.target_ip)
        else:
            ip_layer = IP(dst=self.target_ip)
            
        packet = ip_layer / TCP(dport=port, flags="FPU")
        
        # Если мы подменяем IP, ответ уйдет на фейковый адрес, и мы его тут НЕ поймаем.
        # Поэтому логика меняется:
        if self.spoofed_ip:
            # Просто выбрасываем пакет в сеть (fire-and-forget)
            send(packet, verbose=0)
            return "Packet Sent (Spoofed IP, check target logs later)"
        else:
            # Если сканируем со своего IP, то ждем ответ
            response = sr1(packet, timeout=1.0, verbose=0)
            if response is None:
                return "Open | Filtered"
            elif response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x14: # RST
                    return "Closed"
            return "Unknown"

if __name__ == "__main__":
    target = "192.168.1.1" # Цель
    
    # ТУТ ЗАДАЙ ФЕЙКОВЫЙ IP (например, свободный IP в твоей сети или вообще левый внешний адрес)
    # Если хочешь увидеть результат в консоли, оставь None. Если хочешь проверить скрытность — напиши адрес.
    fake_ip = "192.168.1.99" 
    
    scanner = AdvancedStealthScanner(target, spoofed_ip=fake_ip)
    
    # Список портов для проверки
    ports = [22, 80, 443, 8080, 21, 23, 25]
    
    # Заметаем следы: перемешиваем порты случайным образом
    random.shuffle(ports)
    
    print(f"[*] Запуск продвинутого сканера. Цель: {target}")
    if fake_ip:
        print(f"[!] ВНИМАНИЕ: Включен спуфинг! Пакеты идут от имени: {fake_ip}")
        print("[!] В этом режиме сканер работает «вслепую» — ответы уйдут на подставной IP.")
    print("-" * 60)
    
    try:
        for port in ports:
            result = scanner.xmas_scan(port)
            print(f"[+] Порт {port:4}: {result}")
            
            # Добавляем случайную чиловую задержку от 0.5 до 2 секунд между портами
            delay = random.uniform(0.5, 2.0)
            time.sleep(delay)
            
        print("\n[*] Сканирование завершено успешно.")
    except KeyboardInterrupt:
        print("\n[!] Сканирование прервано.")