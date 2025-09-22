"""
Demo Web para Email Verifier usando API
Interfaz compacta conectada a FastAPI
"""

import streamlit as st
import requests
import json
import time
import pandas as pd
from datetime import datetime

# Configuración
API_BASE_URL = "http://localhost:8000/api/v1"

st.set_page_config(
    page_title="Email Verifier",
    page_icon="",
    layout="wide",
    initial_sidebar_state="expanded"
)

# CSS personalizado (reducido)
st.markdown("""
<style>
    .main-header { font-size: 2.5rem; color: #1f77b4; text-align: center; margin-bottom: 2rem; }
    .status-valid { color: #28a745; font-weight: bold; }
    .status-invalid { color: #dc3545; font-weight: bold; }
    .status-risky { color: #ffc107; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

def init_session_state():
    """Inicializa el estado de la sesión"""
    if 'history' not in st.session_state:
        st.session_state.history = []

def check_api_health():
    """Verificar si la API está funcionando"""
    try:
        response = requests.get(f"{API_BASE_URL}/health", timeout=5)
        return response.status_code == 200
    except:
        return False

def validate_email_via_api(email, level):
    """Validar email usando la API"""
    try:
        payload = {"email": email, "level": level}
        response = requests.post(f"{API_BASE_URL}/validate", json=payload, timeout=60)
        
        if response.status_code == 200:
            return response.json(), None
        else:
            error_detail = response.json().get("detail", "Error desconocido")
            return None, f"Error {response.status_code}: {error_detail}"
            
    except requests.exceptions.Timeout:
        return None, "Timeout: La validación tardó demasiado"
    except requests.exceptions.ConnectionError:
        return None, "Error de conexión: Verifica que la API esté ejecutándose"
    except Exception as e:
        return None, f"Error inesperado: {str(e)}"

def display_verification_result(result):
    """Muestra métricas principales y JSON"""
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Estado", result['overall_status'].upper())
    with col2:
        st.metric("Confianza", f"{result['confidence']}%")
    with col3:
        st.metric("Risk Score", f"{result['risk_score']}/10")
    with col4:
        st.metric("Tiempo", f"{result['processing_time_ms']:.0f} ms")
    
    st.divider()
    st.subheader("Resultado JSON")
    st.json(result)

def verify_single_email():
    """Interfaz para verificar un email individual"""
    st.header("Verificación Individual")
    
    col1, col2 = st.columns([3, 1])
    
    with col1:
        email_input = st.text_input(
            "Introduce el email a verificar:",
            placeholder="usuario@ejemplo.com",
            key="single_email"
        )
    
    with col2:
        level = st.selectbox(
            "Nivel de verificación:",
            ["basic", "standard", "professional"],
            index=1,
            key="single_level"
        )
    
    if st.button("Verificar Email", type="primary"):
        if email_input:
            with st.spinner("Verificando email..."):
                result, error = validate_email_via_api(email_input, level)
                
            if error:
                st.error(f"Error: {error}")
            else:
                st.session_state.history.append(result)
                st.success("Verificación completada")
                display_verification_result(result)
        else:
            st.warning("Por favor, introduce un email válido")

def verify_batch_emails():
    """Interfaz para verificar múltiples emails"""
    st.header("Verificación en Lote")
    
    emails_text = st.text_area(
        "Introduce emails (uno por línea):",
        placeholder="usuario1@ejemplo.com\nusuario2@ejemplo.com",
        height=150,
        key="batch_emails"
    )
    
    uploaded_file = st.file_uploader("O sube un archivo de texto:", type=['txt'], key="batch_file")
    
    level = st.selectbox(
        "Nivel de verificación:",
        ["basic", "standard", "professional"],
        index=0,
        key="batch_level"
    )
    
    if st.button("Verificar Lote", type="primary"):
        emails = []
        
        if emails_text:
            emails.extend([email.strip() for email in emails_text.split('\n') if email.strip()])
        
        if uploaded_file:
            content = uploaded_file.read().decode('utf-8')
            emails.extend([line.strip() for line in content.split('\n') if line.strip()])
        
        if emails:
            progress_bar = st.progress(0)
            status_text = st.empty()
            results = []
            
            for i, email in enumerate(emails):
                progress = (i + 1) / len(emails)
                progress_bar.progress(progress)
                status_text.text(f"Verificando {i+1}/{len(emails)}: {email}")
                
                result, error = validate_email_via_api(email, level)
                if result:
                    results.append(result)
                    st.session_state.history.append(result)
                elif error:
                    st.error(f"Error verificando {email}: {error}")
            
            progress_bar.empty()
            status_text.empty()
            
            if results:
                st.success(f"Verificación completada: {len(results)} emails procesados")
                display_batch_summary(results)
        else:
            st.warning("Por favor, introduce emails o sube un archivo")

def display_batch_summary(results):
    """Muestra resumen de verificación en lote"""
    if not results:
        return
    
    total = len(results)
    valid = sum(1 for r in results if r['overall_status'] == 'valid')
    invalid = sum(1 for r in results if r['overall_status'] == 'invalid')
    risky = sum(1 for r in results if r['overall_status'] == 'risky')
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total", total)
    with col2:
        st.metric("Válidos", valid, f"{valid/total*100:.1f}%")
    with col3:
        st.metric("Riesgosos", risky, f"{risky/total*100:.1f}%")
    with col4:
        st.metric("Inválidos", invalid, f"{invalid/total*100:.1f}%")
    
    # Tabla de resultados
    df_data = []
    for result in results:
        df_data.append({
            'Email': result['email'],
            'Estado': result['overall_status'],
            'Confianza': f"{result['confidence']}%",
            'Risk Score': f"{result['risk_score']}/10"
        })
    
    df = pd.DataFrame(df_data)
    st.dataframe(df, use_container_width=True)
    
    # Descargar resultados
    if st.button("Descargar Resultados JSON"):
        json_str = json.dumps(results, indent=2, ensure_ascii=False)
        st.download_button(
            label="Descargar",
            data=json_str,
            file_name=f"email_verification_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )

def show_history():
    """Muestra el historial de verificaciones"""
    st.header("Historial de Verificaciones")
    
    if not st.session_state.history:
        st.info("No hay verificaciones en el historial")
        return
    
    total_verifications = len(st.session_state.history)
    avg_confidence = sum(r['confidence'] for r in st.session_state.history) / total_verifications
    
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Total Verificaciones", total_verifications)
    with col2:
        st.metric("Confianza Promedio", f"{avg_confidence:.1f}%")
    
    st.subheader("Últimas Verificaciones")
    for result in reversed(st.session_state.history[-10:]):
        with st.expander(f"{result['email']} - {result['overall_status'].upper()}"):
            display_verification_result(result)
    
    if st.button("Limpiar Historial"):
        st.session_state.history = []
        st.rerun()

def get_api_stats():
    """Obtener estadísticas de la API"""
    try:
        response = requests.get(f"{API_BASE_URL}/stats", timeout=5)
        if response.status_code == 200:
            return response.json()
    except:
        pass
    return None

def main():
    """Función principal de la aplicación"""
    init_session_state()
    
    # Header principal
    st.markdown('<h1 class="main-header">Email Verifier</h1>', unsafe_allow_html=True)
    st.markdown("### Sistema Profesional de Verificación de Emails")
    
    # Verificar API
    if not check_api_health():
        st.error("API no disponible. Ejecuta: python run_api.py")
        st.stop()
    
    # Sidebar
    st.sidebar.title("Navegación")
    page = st.sidebar.radio(
        "Selecciona una opción:",
        ["Verificación Individual", "Verificación en Lote", "Historial"]
    )
    
    # Estadísticas API en sidebar
    stats = get_api_stats()
    if stats:
        st.sidebar.divider()
        st.sidebar.subheader("Estadísticas API")
        st.sidebar.write(f"Total validaciones: {stats.get('total_validations', 0)}")
        st.sidebar.write(f"Uptime: {stats.get('uptime_seconds', 0):.0f}s")
    
    st.sidebar.divider()
    st.sidebar.markdown("**Proyecto:** Email Verifier")
    st.sidebar.markdown("**Versión:** 1.0")
    st.sidebar.markdown("**API:** Conectada")
    
    # Contenido principal
    if page == "Verificación Individual":
        verify_single_email()
    elif page == "Verificación en Lote":
        verify_batch_emails()
    elif page == "Historial":
        show_history()

if __name__ == "__main__":
    main()