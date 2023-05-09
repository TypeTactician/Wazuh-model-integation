import os
import sys

def restart_program():
    python = sys.executable
    os.execl(python, python, *sys.argv)

try:
    import subprocess
    import sys

    REQUIRED_MODULES = ['requests', 'numpy', 'tensorflow', 'keras']

    for module in REQUIRED_MODULES:
        try:
            __import__(module)
        except ImportError:
            print(f"{module} not found. Attempting to install with pip...")
            try:
                subprocess.run([sys.executable, "-m", "pip", "install", module], check=True)
                print(f"{module} installed successfully!")
            except subprocess.CalledProcessError:
                print(f"Failed to install {module}. Please install it manually.")

    import requests
    import numpy as np
    from tensorflow import keras
    import os
    import json
    from elasticsearch import Elasticsearch

    api_ip = input("Enter the Wazuh API IP address: ")
    api_port = input("Enter the Wazuh API port: ")
    api_username = input("Enter the Wazuh API username: ")
    api_password = input("Enter the Wazuh API password: ")
    
    es = Elasticsearch(
        [f"{wazuh_ip}:{wazuh_port}"],
        http_auth=(wazuh_username, wazuh_password),
        scheme="http",
        port=wazuh_port,
    )

    def get_alerts():
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"_index": "wazuh-alerts-*"}},
                        {"match": {"alert.status": "opened"}},
                        {"match": {"event.kind": "alert"}}
                    ]
                }
            },
            "size": 100
        }
        res = es.search(index="*", body=query)
        alerts = [alert["_source"] for alert in res["hits"]["hits"]]
        return alerts

    def delete_alert(alert_id):
        url = f"http://{api_ip}:{api_port}/alerts/{alert_id}"
        response = requests.delete(url, auth=(api_username, api_password))
        response.raise_for_status()

    model_path = input("Enter the path to the trained model file: ")
    model = keras.models.load_model(model_path)

    log_path = input("Enter the path to the log file: ")

    if not os.path.exists(log_path):
        with open(log_path, 'w') as f:
            f.write('Wazuh log\n')

    def is_alert_false(alert):
        features = [
            alert['srcip'],
            alert['dstip'],
            alert['rule']['level'],
            alert['rule']['frequency'],
            alert['rule']['id'],
            alert['rule']['category'],
            alert['rule']['user'],
            alert['rule']['description'],
            alert['rule']['reference'],
            alert['rule']['tags']
        ]
        features_array = np.array(features).reshape(1, -1)
        label = model.predict_classes(features_array)
        return label[0] == 0

    def remove_false_alerts():
        alerts_list = get_alerts()
        removed_alerts = []
        for alert in alerts_list:
            if is_alert_false(alert):
                delete_alert(alert["_id"])
                with open(log_path, 'a') as f:
                    f.write(f"False alert removed: {alert}\n")
                removed_alerts.append(alert)
        return removed_alerts

    def menu():
        while True:
            print("\nWazuh False Alert Remover\n")
            print("1. Remove false alerts")
            print("2. Quit\n")
            choice = input("Enter choice (1 or 2): ")
            if choice == "1":
                print("\nRemoving false alerts...")
                removed_alerts_count = remove_false_alerts()
                print(f"Removed {removed_alerts_count} false alerts.")
            elif choice == "2":
                print("\nGoodbye!")
                break
            else:
                print("\nInvalid choice. Please try again.")

    menu()
except Exception as e:
    print(f"Error: {e}")
    while True:
        answer = input("Do you want to restart the program? (y/n): ")
        if answer.lower() == "y":
            restart_program()
        elif answer.lower() == "n":
            break
        else:
            print("Invalid input. Please enter 'y' or 'n'.")
