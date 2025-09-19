"""
Demo Web para Email Verifier usando Streamlit
Interfaz profesional para mostrar al tutor
"""

import streamlit as st
import json
import time
import pandas as pd
from datetime import datetime
import sys
import os

# Agregar src al path
sys.path.append(os.path.join(os.path.dirname(__file__), '.'))

try:
    from src.email_verifier import EmailVerifier
except ImportError:
    st.error("Error: No se puede importar EmailVerifier. Verifica que los archivos estén en src/")
    st.stop()

# Configuración de la página
st.set_page_config(
    page_title="Email Verifier",
    page_icon="",
    layout="wide",
    initial_sidebar_state="expanded"
)

# CSS personalizado
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .status-valid {
        color: #28a745;
        font-weight: bold;
    }
    .status-invalid {
        color: #dc3545;
        font-weight: bold;
    }
    .status-risky {
        color: #ffc107;
        font-weight: bold;
    }
    .metric-box {
        background-color: #f8f9fa;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #1f77b4;
    }
</style>
""", unsafe_allow_html=True)

def init_session_state():
    """Inicializa el estado de la sesión"""
    if 'verifier' not in st.session_state:
        st.session_state.verifier = EmailVerifier()
    if 'history' not in st.session_state:
        st.session_state.history = []

def format_status(status):
    """Formatea el status con colores"""
    status_upper = status.upper()
    if status == "valid":
        return f'<span class="status-valid">✓ {status_upper}</span>'
    elif status == "invalid":
        return f'<span class="status-invalid">✗ {status_upper}</span>'
    elif status == "risky":
        return f'<span class="status-risky">⚠ {status_upper}</span>'
    else:
        return status_upper

def display_verification_result(result):
    """Muestra solo las métricas principales y el JSON"""
    
    # Métricas principales
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Estado", result['overall_status'].upper())
    
    with col2:
        confidence = result['confidence']
        st.metric("Confianza", f"{confidence}%")
    
    with col3:
        risk_score = result['risk_score']
        st.metric("Risk Score", f"{risk_score}/10")
    
    with col4:
        processing_time = result['processing_time_ms']
        st.metric("Tiempo", f"{processing_time:.0f} ms")
    
    st.divider()
    
    # Mostrar JSON completo
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
    
    if st.button(" Verificar Email", type="primary"):
        if email_input:
            with st.spinner("Verificando email..."):
                start_time = time.time()
                result = st.session_state.verifier.verify_email(email_input, level)
                
            # Agregar al historial
            st.session_state.history.append(result)
            
            st.success(f"Verificación completada en {time.time() - start_time:.2f} segundos")
            display_verification_result(result)
        else:
            st.warning("Por favor, introduce un email válido")

def verify_batch_emails():
    """Interfaz para verificar múltiples emails"""
    st.header("Verificación en Lote")
    
    # Opción 1: Textarea
    emails_text = st.text_area(
        "Introduce emails (uno por línea):",
        placeholder="usuario1@ejemplo.com\nusuario2@ejemplo.com\nusuario3@ejemplo.com",
        height=150,
        key="batch_emails"
    )
    
    # Opción 2: Subir archivo
    uploaded_file = st.file_uploader(
        "O sube un archivo de texto:",
        type=['txt', 'csv'],
        key="batch_file"
    )
    
    level = st.selectbox(
        "Nivel de verificación:",
        ["basic", "standard", "professional"],
        index=0,  # Basic por defecto para lotes
        key="batch_level"
    )
    
    if st.button(" Verificar Lote", type="primary"):
        emails = []
        
        # Procesar emails del textarea
        if emails_text:
            emails.extend([email.strip() for email in emails_text.split('\n') if email.strip()])
        
        # Procesar archivo subido
        if uploaded_file:
            content = uploaded_file.read().decode('utf-8')
            if uploaded_file.name.endswith('.csv'):
                # Asumir que los emails están en la primera columna
                lines = content.split('\n')[1:]  # Saltar header
            else:
                lines = content.split('\n')
            
            emails.extend([line.split(',')[0].strip() for line in lines if line.strip()])
        
        if emails:
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            results = []
            
            for i, email in enumerate(emails):
                progress = (i + 1) / len(emails)
                progress_bar.progress(progress)
                status_text.text(f"Verificando {i+1}/{len(emails)}: {email}")
                
                try:
                    result = st.session_state.verifier.verify_email(email, level)
                    results.append(result)
                    st.session_state.history.append(result)
                except Exception as e:
                    st.error(f"Error verificando {email}: {str(e)}")
            
            progress_bar.empty()
            status_text.empty()
            
            st.success(f"Verificación completada: {len(results)} emails procesados")
            
            # Mostrar resumen
            display_batch_summary(results)
        else:
            st.warning("Por favor, introduce emails o sube un archivo")

def display_batch_summary(results):
    """Muestra resumen de verificación en lote"""
    if not results:
        return
    
    # Estadísticas generales
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
            'Risk Score': f"{result['risk_score']}/10",
            'Indicadores': len(result['fraud_indicators'])
        })
    
    df = pd.DataFrame(df_data)
    st.dataframe(df, use_container_width=True)
    
    # Descargar resultados
    if st.button(" Descargar Resultados JSON"):
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
    
    # Estadísticas del historial
    total_verifications = len(st.session_state.history)
    avg_confidence = sum(r['confidence'] for r in st.session_state.history) / total_verifications
    avg_time = sum(r['processing_time_ms'] for r in st.session_state.history) / total_verifications
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Verificaciones", total_verifications)
    with col2:
        st.metric("Confianza Promedio", f"{avg_confidence:.1f}%")
    with col3:
        st.metric("Tiempo Promedio", f"{avg_time:.0f} ms")
    
    # Mostrar últimas verificaciones
    st.subheader("Últimas Verificaciones")
    for i, result in enumerate(reversed(st.session_state.history[-10:])):  # Últimas 10
        with st.expander(f"{result['email']} - {result['overall_status'].upper()}"):
            display_verification_result(result)
    
    # Limpiar historial
    if st.button(" Limpiar Historial"):
        st.session_state.history = []
        st.rerun()

def show_stats():
    """Muestra estadísticas del verificador"""
    st.header("Estadísticas del Sistema")
    
    stats = st.session_state.verifier.get_stats()
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Base de Datos")
        st.write(f"• Dominios desechables: {stats['disposable_domains']}")
        st.write(f"• Dominios gratuitos: {stats['free_domains']}")
        st.write(f"• Dominios en blacklist: {stats['blacklist_domains']}")
        st.write(f"• Patrones sospechosos: {stats['suspicious_patterns']}")
    
    with col2:
        st.subheader("Configuración DNS")
        st.write(f"• Timeout DNS: {stats['dns_timeout']} segundos")
        st.write(f"• Selectores DKIM: {stats['dkim_selectors']}")
        
        st.subheader("Validaciones Implementadas")
        st.write(" 1-6: Validaciones básicas")
        st.write(" 7-12: Validaciones DNS")
        st.write(" 13-23: En desarrollo")

def main():
    """Función principal de la aplicación"""
    
    # Inicializar sesión
    init_session_state()
    
    # Header principal
    st.markdown('<h1 class="main-header"> Email Verifier </h1>', unsafe_allow_html=True)
    st.markdown("### Sistema Profesional de Verificación de Emails")
    
    # Sidebar
    st.sidebar.title("Navegación")
    page = st.sidebar.radio(
        "Selecciona una opción:",
        ["Verificación Individual", "Verificación en Lote", "Historial", "Estadísticas"]
    )
    
    st.sidebar.divider()
    st.sidebar.markdown("**Proyecto:** Email Verifier")
    st.sidebar.markdown("**Versión:** 1.0")
    st.sidebar.markdown("**Estado:** 12/23 validaciones")
    
    # Contenido principal
    if page == "Verificación Individual":
        verify_single_email()
    elif page == "Verificación en Lote":
        verify_batch_emails()
    elif page == "Historial":
        show_history()
    elif page == "Estadísticas":
        show_stats()

if __name__ == "__main__":
    main()