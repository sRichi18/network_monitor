import pandas as pd
import matplotlib.pyplot as plt
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle
from datetime import datetime
import os

# === CONFIGURACIÓN ===
INPUT_FILE = "captures/network_events.csv"
REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

# === Cargar datos ===
try:
    df = pd.read_csv(INPUT_FILE)
except FileNotFoundError:
    print("❌ No se encontró el archivo CSV. Ejecuta primero el monitor para generar datos.")
    exit()

# === Estadísticas básicas ===
total_events = len(df)
event_counts = df["Evento"].value_counts()
top_sources = df["IP_Origen"].value_counts().head(5)
top_protocols = df["Protocolo"].value_counts()

# === Crear gráfico de eventos ===
plt.figure(figsize=(6, 4))
event_counts.plot(kind="bar", color="#4682B4")
plt.title("Distribución de eventos detectados")
plt.xlabel("Tipo de evento")
plt.ylabel("Cantidad")
plt.tight_layout()
chart_path = os.path.join(REPORTS_DIR, "event_distribution.png")
plt.savefig(chart_path)
plt.close()

# === Crear documento PDF ===
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
pdf_filename = os.path.join(REPORTS_DIR, f"network_report_{timestamp}.pdf")
doc = SimpleDocTemplate(pdf_filename, pagesize=A4)
styles = getSampleStyleSheet()
elements = []

# === Título ===
elements.append(Paragraph("<b>Network Traffic Monitor - Reporte de Actividad</b>", styles["Title"]))
elements.append(Spacer(1, 12))
elements.append(Paragraph(f"Fecha de generación: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]))
elements.append(Paragraph(f"Total de eventos analizados: <b>{total_events}</b>", styles["Normal"]))
elements.append(Spacer(1, 12))

# === Gráfico ===
elements.append(Image(chart_path, width=400, height=300))
elements.append(Spacer(1, 12))

# === Tabla: IPs más activas ===
elements.append(Paragraph("<b>Top 5 IPs origen más activas</b>", styles["Heading3"]))
data_ips = [["IP Origen", "Eventos"]] + list(zip(top_sources.index, top_sources.values))
table_ips = Table(data_ips, colWidths=[200, 100])
table_ips.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#003366")),
    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
]))
elements.append(table_ips)
elements.append(Spacer(1, 12))

# === Tabla: protocolos más usados ===
elements.append(Paragraph("<b>Protocolos más utilizados</b>", styles["Heading3"]))
data_proto = [["Protocolo", "Eventos"]] + list(zip(top_protocols.index, top_protocols.values))
table_proto = Table(data_proto, colWidths=[200, 100])
table_proto.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#003366")),
    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
]))
elements.append(table_proto)
elements.append(Spacer(1, 12))

# === Resumen textual ===
elements.append(Paragraph("<b>Resumen general</b>", styles["Heading3"]))
summary = (
    f"El sistema analizó {total_events} eventos en total. "
    f"Se detectaron {len(event_counts)} tipos de actividad distintos, siendo "
    f"'{event_counts.index[0]}' el más frecuente. "
    f"Las IPs más activas corresponden a {', '.join(top_sources.index[:3])}."
)
elements.append(Paragraph(summary, styles["Normal"]))

# === Generar PDF ===
doc.build(elements)

print(f"✅ Reporte generado correctamente: {pdf_filename}")