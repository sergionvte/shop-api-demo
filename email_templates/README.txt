Plantillas de correo propias del proyecto
=========================================

Lo que pongas aquí gana a las plantillas de serie (app/email/templates/), fichero a
fichero. apigen nunca toca esta carpeta.

Estructura: <idioma>/<plantilla>.subject.txt, .txt y .html. Ejemplo, para cambiar solo el
asunto del correo de recuperación en español:

    email_templates/es/password_reset.subject.txt

Para empezar desde una copia de las de serie:

    apigen email eject                      # todas (y el layout)
    apigen email eject password_reset --lang es
    apigen email preview password_reset     # HTML y texto en var/mail/preview/

Plantillas de serie: password_reset, verify_email, email_change_confirm,
email_change_requested, email_changed, password_changed, account_exists, test.
Layout común: _layout.html, _button.html y _footer.txt.

Variables comunes: brand.name, brand.url, brand.logo_url, brand.color,
brand.support_email, brand.footer (del .env: MAIL_BRAND_*, MAIL_SUPPORT_EMAIL,
MAIL_FOOTER), labels, language, year. Enlaces: action_url y expires_in.

Reglas:
- Jinja2 en sandbox, con autoescape en .html y modo estricto (una variable que no
  existe es un error). `apigen check` renderiza todas y avisa de los errores.
- No pongas aquí direcciones ni datos fijos: marca y contacto van en el .env.
- Plantillas nuevas para tus propios correos: créalas aquí y envíalas con
  `app.email.send_email(session, to=[...], template="mi_plantilla", context={...})`.
- Un idioma nuevo: crea la carpeta (p. ej. fr/) y añádelo a MAIL_LANGUAGES.
