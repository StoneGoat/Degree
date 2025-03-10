import xml.etree.ElementTree as ET

class XML_Parser:
  def get_alert_items(file_path):
    # Parse the XML file.
    tree = ET.parse(file_path)
    root = tree.getroot()

    alert_items = []
    # Loop through each site element.
    for site in root.findall('site'):
        # Find the alerts element inside the site.
        alerts = site.find('alerts')
        if alerts is not None:
            # Retrieve all alertitem elements.
            for alert in alerts.findall('alertitem'):
                alert_items.append(alert)
    return alert_items
  
  if __name__ == "__main__":
    file_path = "scan-report.xml"
    items = get_alert_items(file_path)
    print("Found", len(items), "alert items.")
    # Example: print the alert names.
    for alert in items:
        alert_name = alert.find('alert').text if alert.find('alert') is not None else "N/A"
        print("Alert:", alert_name)
