import streamlit as st
import streamlit_authenticator as st_auth


COOKIE_EXPIRY_DAYS = 30


def main():
    authenticator = st_auth.Authenticator(
        {"usernames": {"teste": {"name": "testando", "password": "test"}}},
        cookie_name="random_cookie_name",
        signature_key="random_signature_key",
        cookie_duration_days=COOKIE_EXPIRY_DAYS,
    )

    if "cliclou_registrar" not in st.session_state:
        st.session_state["cliclou_registrar"] = False

    if st.session_state["cliclou_registrar"] == False:
        login_form(authenticator=authenticator)
    else:
        usuario_form()


def login_form(authenticator):
    name, authenticator_status, username = authenticator.login("Login")
    if authenticator_status:
        authenticator.logout("Logout", main)
        st.title("Area de Dashboard")
        st.write(f"*{name} está logado")
    elif authenticator_status == False:
        st.error("Usuário ou senha incorretos.")
    elif authenticator_status == None:
        st.warning("Por favor informe um usuário e senha.")
        cliclou_em_registrar = st.button("Registrar")
        if cliclou_em_registrar:
            st.session_state["cliclou_registrar"] = True
            st.rerun()


def confirm_msg():
    hashed_password = stauth.Hasher([st.session_state.pswrd]).generate()
    if st.session_state.pswrd != st.session_state.confirm_pswrd:
        st.warning("Senhas não conferem")
    elif "consulta_nome()":
        st.warning("Nome de usuário já existe.")
    else:
        "add_registro()"
        st.success("Registro efetuado!")


def usuario_form():
    with st.form(key="formulario", clear_on_submit=True):
        nome = st.text_input("Nome", key="nome")
        username = st.text_input("Usuário", key="user")
        password = st.text_input("Senha", key="pswrd", type="password")
        confirm_password = st.text_input(
            "Confirmar senha", key="confirmar_pswrd", type="password"
        )
        submit = st.form_submit_button(
            "Salvar",
            on_click=confirm_msg,
        )
        cliclou_em_fazer_login = st.button("Fazer login")


    if cliclou_em_fazer_login:
        st.session_state["cliclou_registrar"] = False
        st.rerun()


if __name__ == "__main__":
    main()
