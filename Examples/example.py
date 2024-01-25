from NetGuard import NetworkAnalyzer  # Reemplaza "MiLibreria" con el nombre real de tu librería

if __name__ == "__main__":
    initial_target_ip = "192.168.1.1"  # Establece el objetivo inicial
    analyzer = NetworkAnalyzer(target_ip=initial_target_ip, threshold=10)

    try:
        analyzer_thread = threading.Thread(target=analyzer.start_analysis)
        analyzer_thread.start()

        while True:
            new_target_ip = input("Ingrese la nueva IP de destino (o presione Enter para mantener la actual): ")
            if new_target_ip:
                analyzer.set_target_ip(new_target_ip)
                print(f"Objetivo actualizado a: {new_target_ip}")
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("Análisis de red detenido.")
