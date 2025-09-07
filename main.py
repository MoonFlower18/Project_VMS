import requests
import nmap
import time
from datetime import datetime
import os

SERVER_URL = "http://127.хх.хх.хх:хххх/upload"

scanner1 = nmap.PortScanner()
scanner2 = nmap.PortScanner()

def scan_network(ip_range):
    try:
        print(f"Сканирование IP-адреса -> {ip_range}...")
        scanner1.scan(hosts=ip_range, arguments='-sV')  # скан TCP
        scanner2.scan(hosts=ip_range, arguments='-sU')  # скан UDP

        results = []
        for host in scanner1.all_hosts():
            print(f"\n>>>>>> Результаты для хоста: {host} <<<<<<\n")

            print(">>> Открытые TCP порты: ")
            if 'tcp' in scanner1[host]:
                for port in scanner1[host]['tcp']:
                    state = scanner1[host]['tcp'][port]['state']
                    service = scanner1[host]['tcp'][port]['name']
                    if state == 'open':
                        results.append({
                            'ip': host,
                            'port': port,
                            'state': state,
                            'service': service
                        })

                        if port == 21:
                            print(f"\nIP: {host}, Port: {port}, State: {state}, Service: {service}")
                            print("[ WARNING ] Порт 21 (FTP) используется для передачи файлов. "
                                  "Отправка данных в открытом виде делает FTP уязвимым для перехвата. "
                                  "Рекомендуем использовать FTPS или SFTP для защиты информации.")

                        elif port == 22:
                            print(f"\nIP: {host}, Port: {port}, State: {state}, Service: {service}")
                            print("[ WARNING ] Порт 22 (SSH) используется для защищенного удаленного доступа к серверам. "
                                  "Часто подвержен атакам подбора паролей. "
                                  "Рекомендуется использовать ключи SSH вместо паролей для повышения безопасности.")

                        elif port == 23:
                            print(f"\nIP: {host}, Port: {port}, State: {state}, Service: {service}")
                            print("[ WARNING ] Порт 23 (Telnet) используется для удаленного доступа и управления устройствами. "
                                  "Как и FTP, Telnet передает данные в открытом виде. "
                                  "Рекомендуем полностью отказаться от Telnet в пользу SSH.")

                        elif port == 80:
                            print(f"\nIP: {host}, Port: {port}, State: {state}, Service: {service}")
                            print("[ WARNING ] Порт 80 (HTTP) применяется для доступа к веб-страницам. "
                                  "Может быть атакован с помощью XSS, SQL-инъекций и других уязвимостей веб-приложений. "
                                  "Рекомендуем использовать HTTPS для шифрования данных.")

                        elif port == 135:
                            print(f"\nIP: {host}, Port: {port}, State: {state}, Service: {service}")
                            print("[ WARNING ] Порт 135 (RPC) предназначен для выполнения команд и заданий."
                                  "Может быть осуществлена загрузка стороннего вредоносного ПО."
                                  "Рекомендуем настроить доступ только доверенным пользователям или адресам.")

                        elif port == 139:
                            print(f"\nIP: {host}, Port: {port}, State: {state}, Service: {service}")
                            print("[ WARNING ] Порт 139 предназначен для удаленного подключения к компьютеру."
                                  "Злоумышленники могут использовать данный порт для инициирования таких атак, как программы-вымогатели, утечки данных и шпионаж."
                                  "Рекомендуем отключить удалённый доступ или предоставить его только доверенным адресам внутри компании.")

                        elif port == 443:
                            print(f"\nIP: {host}, Port: {port}, State: {state}, Service: {service}")
                            print("[ WARNING ] Порт 443 (HTTPS) используется для защищенной передачи данных через интернет. "
                                  "Хоть HTTPS и шифрует данные, уязвимости в SSL/TLS могут позволить злоумышленникам их перехватывать. "
                                  "Поэтому крайне важно поддерживать сертификаты и настройки безопасности в актуальном состоянии.")

                        elif port == 445:
                            print(f"\nIP: {host}, Port: {port}, State: {state}, Service: {service}")
                            print("[ WARNING ] Порт 445 (SMB) применяется для обмена файлами в сетях Windows. "
                                  "Может быть использован для распространения вредоносного ПО. "
                                  "Рекомендуем отключить SMB, если он не нужен, или использовать актуальные версии протокола.")

                        elif port == 3306:
                            print(f"\nIP: {host}, Port: {port}, State: {state}, Service: {service}")
                            print("[ WARNING ] Порт 3306 (MySQL) применяется для работы с базами данных MySQL. "
                                  "Неконтролируемый доступ к базе данных может привести к утечкам информации. "
                                  "Рекомендуем ограничить доступ к этому порту до авторизованных пользователей.")

                        elif port == 3389:
                            print(f"\nIP: {host}, Port: {port}, State: {state}, Service: {service}")
                            print("[ WARNING ] Порт 3389 (RDP) применяется для доступа к службе удаленных рабочих столов в ОС Windows. "
                                  "Часто становится целью атак из-за слабых паролей и уязвимостей данной системы. "
                                  "Рекомендуем ограничивать доступ по IP и использовать многофакторную аутентификацию.")

                        elif port == 5432:
                            print(f"\nIP: {host}, Port: {port}, State: {state}, Service: {service}")
                            print("[ WARNING ] Порт 5432 (PostgreSQL) используется для доступа к базам данных PostgreSQL. "
                                  "Аналогично MySQL, открытый порт может быть использован для атак. "
                                  "Рекомендуем ограничить доступ и использовать надежные пароли.")

                        elif port == 5900:
                            print(f"\nIP: {host}, Port: {port}, State: {state}, Service: {service}")
                            print("[ WARNING ] Порт 5900 (VNC) применяется для удаленного доступа к графическому интерфейсу. "
                                  "Может быть подвержен атакам из-за слабых паролей. "
                                  "Рекомендуем использовать VPN для защищенного доступа.")

                        else:
                            print(f"\nIP: {host}, Port: {port}, State: {state}, Service: {service}")
                            print("[ INFO ] Аномалий не обнаружено.")


            print("\n>>> Открытые UDP порты: ")
            if 'udp' in scanner2[host]:
                for port in scanner2[host]['udp']:
                    state = scanner2[host]['udp'][port]['state']
                    service = scanner2[host]['udp'][port]['name']
                    if state in ['open', 'open|filtered']:  # обработка состояний
                        results.append({
                            'ip': host,
                            'port': port,
                            'state': state,
                            'service': service
                        })

                        if port == 53:
                            print(f"\nIP: {host}, Port: {port}, State: {state}, Service: {service}")
                            print("[ WARNING ] Порт может давать доступ к уязвимости DNS Amplification."
                                  "Рекомендуем выключить на DNS-сервере рекурсивные ответы (т.е. запретить ему "
                                  "отвечать на запросы, касающиеся зон, которые он не обслуживает)")

                        elif port == 111:
                            print(f"\nIP: {host}, Port: {port}, State: {state}, Service: {service}")
                            print("[ WARNING ] Порт может давать доступ к уязвимости, которая возникает из-за "
                                  "особенностей протокола ONC RPC, используемого в частности, для работы NFS-демона. "
                                  "Если на вашем сервере не используется сетевая файловая система NFS, то вы можете остановить или удалить данный сервис. "
                                  "Если же вы используете NFS - ограничьте доступ к порту 111/udp на вашем сервере.")

                        elif port == 123:
                            print(f"\nIP: {host}, Port: {port}, State: {state}, Service: {service}")
                            print("[ WARNING ] Порт стать причиной атаки через протокол времени NTP Amplification ("
                                  "CVE-2013-5211).")

                        elif port == 137:
                            print(f"\nIP: {host}, Port: {port}, State: {state}, Service: {service}")
                            print("[ WARNING ] Порт может использоваться для поиска информации на других компьютерах.")

                        elif port == 8211:
                            print(f"\nIP: {host}, Port: {port}, State: {state}, Service: {service}")
                            print("[ WARNING ] Порт может давать доступ к уязвимой службе Aruba's Access Point."
                                  "Тип уязвимости: CMD-инъекция, CVE-2024-42505-42507.")

                        else:
                            print(f"\nIP: {host}, Port: {port}, State: {state}, Service: {service}")
                            print("[ INFO ] Аномалий не обнаружено.")

        return results
    except Exception as e:
        print(f"Ошибка сканирования: {e}")
        return []

def format_time(timestamp):
    return timestamp.strftime("%H:%M:%S")

def send_results_to_server(results):
    if not results:
        print("Нет открытых портов.")

    try:
        response = requests.post(SERVER_URL, json=results)
        if response.status_code == 200:
            print("Результаты успешно отправлены на сервер.\nВремя проверки:", format_time(datetime.now()))
        else:
            print("Ошибка при отправке данных на сервер:", response.text)
    except Exception as e:
        print(f"Ошибка сетевого запроса: {e}")


if __name__ == "__main__":
    ip_range = '192.168.xx.xx'  # можно указать свой IP для сканирования

    while True:
        scan_results = scan_network(ip_range)
        send_results_to_server(scan_results)
        time.sleep(60)
