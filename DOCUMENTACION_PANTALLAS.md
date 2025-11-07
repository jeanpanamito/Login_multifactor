# Documentación de Pantallas - Sistema de Login Multifactor

## Índice
1. [Pantalla de Registro](#1-pantalla-de-registro)
2. [Pantalla de Activación](#2-pantalla-de-activación)
3. [Pantalla de Login](#3-pantalla-de-login)
4. [Pantalla de MFA (Multi-Factor Authentication)](#4-pantalla-de-mfa-multi-factor-authentication)
5. [Pantalla de Recuperación de Contraseña](#5-pantalla-de-recuperación-de-contraseña)
6. [Pantalla de Desbloqueo de Cuenta](#6-pantalla-de-desbloqueo-de-cuenta)
7. [Pantalla de Logout](#7-pantalla-de-logout)

---

## 1. Pantalla de Registro

**URL:** `/register/`  
**Método:** GET, POST  
**Requisito del Sistema:** RS1 - Registro y Activación de Nuevos Usuarios

### Funcionalidad
Permite a nuevos usuarios registrarse en el sistema. El sistema genera automáticamente un username y una contraseña temporal, y envía un código de activación al correo electrónico o teléfono del usuario.

### Campos del Formulario
- **first_name** (texto, requerido): Nombre del usuario
- **last_name** (texto, requerido): Apellido del usuario
- **email** (email, requerido): Correo electrónico del usuario
- **phone_number** (texto, opcional): Número de teléfono del usuario
- **activation_method** (selección, requerido): Método de activación
  - Opciones: "Correo electrónico" o "Teléfono"

### Flujo de Funcionamiento

1. **Usuario completa el formulario:**
   - Ingresa sus datos personales (nombre, apellido, email, teléfono opcional)
   - Selecciona el método de activación (email o teléfono)

2. **Sistema procesa el registro:**
   - Genera un username único basado en el email
   - Genera una contraseña temporal aleatoria de 12 caracteres
   - Crea el usuario con `is_active=False`
   - Genera un código de activación de 6 dígitos
   - Establece la fecha de expiración del código (30 minutos)

3. **Sistema envía notificación:**
   - Si el método es email: Envía un correo con:
     - Código de activación
     - Username generado
     - Contraseña temporal
   - Si el método es teléfono: Simula envío SMS (en consola)

4. **Sistema registra el evento:**
   - Crea un registro en `AccessAttempt` con tipo `USER_CREATION`
   - Registra IP y dispositivo del usuario

5. **Usuario ve sus credenciales:**
   - Se muestra en pantalla el username y contraseña temporal
   - Se indica que debe activar su cuenta

### Requisitos Cumplidos
- ✅ **RS1 F1.1:** Formulario de registro con todos los campos requeridos
- ✅ **RS1 F1.2:** Creación de cuenta con username y password_hash generados
- ✅ **RS1 F1.3:** Generación de código de activación único con expiración
- ✅ **RS1 F1.4:** Envío de notificación al email o teléfono
- ✅ **RS3 F3.1:** Registro de creación de usuario en AccessAttempt

### Próximo Paso
El usuario debe ir a la pantalla de **Activación** para activar su cuenta con el código recibido.

---

## 2. Pantalla de Activación

**URL:** `/activate/`  
**Método:** GET, POST  
**Requisito del Sistema:** RS1 - Registro y Activación de Nuevos Usuarios

### Funcionalidad
Permite a los usuarios activar su cuenta ingresando el código de activación que recibieron por email o SMS.

### Campos del Formulario
- **username** (texto, requerido): Username asignado durante el registro
- **code** (texto, requerido, 6 dígitos): Código de activación recibido

### Flujo de Funcionamiento

1. **Usuario ingresa sus datos:**
   - Ingresa el username que recibió
   - Ingresa el código de activación de 6 dígitos

2. **Sistema valida el código:**
   - Busca el usuario por username
   - Verifica que el código coincida con `activation_code`
   - Verifica que el código no haya expirado (`activation_expires_at`)
   - Verifica que la cuenta no esté ya activa

3. **Sistema activa la cuenta:**
   - Si el código es válido:
     - Establece `is_active=True`
     - Marca email o teléfono como verificado según el método
     - Limpia el código de activación
   - Si el código es inválido o expirado:
     - Muestra mensaje de error

4. **Usuario puede iniciar sesión:**
   - Una vez activada, el usuario puede ir a la pantalla de Login

### Requisitos Cumplidos
- ✅ **RS1 F1.5:** Interfaz para ingresar el código de activación
- ✅ **RS1 F1.6:** Validación y activación usando `User.activate(code)`

### Próximo Paso
El usuario debe ir a la pantalla de **Login** para iniciar sesión.

---

## 3. Pantalla de Login

**URL:** `/login/`  
**Método:** GET, POST  
**Requisito del Sistema:** RS2 - Control de Ingreso con 2FA (MFA)

### Funcionalidad
Permite a los usuarios iniciar sesión con su username y contraseña. Después de validar las credenciales, el sistema redirige al usuario a la verificación MFA.

### Campos del Formulario
- **username** (texto, requerido): Username del usuario
- **password** (contraseña, requerido): Contraseña del usuario

### Flujo de Funcionamiento

1. **Usuario ingresa credenciales:**
   - Ingresa username y contraseña

2. **Sistema verifica estado de la cuenta:**
   - Verifica si la cuenta está bloqueada (`is_locked` o `locked_until`)
   - Si está bloqueada, redirige a la pantalla de Desbloqueo

3. **Sistema valida credenciales:**
   - Autentica username y password usando Django `authenticate()`

4. **Si las credenciales son correctas:**
   - Registra intento exitoso en `AccessAttempt`
   - Guarda el ID del usuario en sesión (`pending_user_id`)
   - Detecta métodos MFA activos del usuario
   - Si no hay métodos MFA configurados, crea uno basado en `mfa_method` del usuario
   - Genera y envía código MFA según el método configurado
   - Redirige a la pantalla de MFA

5. **Si las credenciales son incorrectas:**
   - Registra intento fallido en `AccessAttempt`
   - Incrementa contador de intentos fallidos
   - Verifica si hay 4 o más intentos fallidos en los últimos 15 minutos
   - Si hay 4 o más intentos fallidos:
     - Bloquea la cuenta automáticamente (`User.lock()`)
     - Redirige a la pantalla de Desbloqueo
   - Muestra mensaje de error

### Requisitos Cumplidos
- ✅ **RS2 F2.1:** Validación de username y password
- ✅ **RS2 F2.2:** Detección de métodos MFA activos
- ✅ **RS2 F2.4:** Generación y envío de código MFA
- ✅ **RS3 F3.2:** Registro de intentos de acceso
- ✅ **RS6 F6.2-F6.4:** Verificación y bloqueo automático por intentos fallidos

### Próximo Paso
El usuario es redirigido a la pantalla de **MFA** para completar la autenticación.

---

## 4. Pantalla de MFA (Multi-Factor Authentication)

**URL:** `/mfa/`  
**Método:** GET, POST  
**Requisito del Sistema:** RS2 - Control de Ingreso con 2FA (MFA)

### Funcionalidad
Permite a los usuarios completar la autenticación mediante el segundo factor de autenticación configurado (código por email/SMS, pregunta de seguridad, TOTP, o llave USB).

### Campos del Formulario
- **code** (texto, opcional): Código de verificación (para EMAIL, SMS, TOTP, USB_KEY)
- **answer** (texto, opcional): Respuesta a pregunta de seguridad (para SECURITY_QUESTIONS)

### Tipos de MFA Soportados

#### 1. **EMAIL** - Código por Correo
- El sistema envía un código de 6 dígitos al email del usuario
- El usuario ingresa el código recibido
- El código expira en 10 minutos

#### 2. **SMS** - Código por SMS
- El sistema envía un código de 6 dígitos al teléfono del usuario
- El usuario ingresa el código recibido
- El código expira en 10 minutos

#### 3. **SECURITY_QUESTIONS** - Preguntas Secretas
- El sistema muestra una pregunta de seguridad configurada
- El usuario ingresa la respuesta
- La respuesta se valida de forma case-insensitive

#### 4. **TOTP** - Aplicación OTP (Google Authenticator, Authy)
- El usuario abre su aplicación de autenticación
- Ingresa el código de 6 dígitos generado por la app
- El sistema valida el token usando `django-otp`

#### 5. **USB_KEY** - Llave USB (YubiKey)
- El usuario conecta su llave USB
- Presiona el botón de la llave para generar un token
- Ingresa el token generado

### Flujo de Funcionamiento

1. **Sistema muestra el método MFA:**
   - Obtiene el método MFA activo del usuario desde la sesión
   - Muestra la interfaz correspondiente según el tipo de método

2. **Usuario ingresa el código/respuesta:**
   - Ingresa el código o respuesta según el método

3. **Sistema valida el segundo factor:**
   - Llama a `MFAMethod.validate(input_value)`
   - Según el tipo de método:
     - **EMAIL/SMS:** Valida el código contra `VerificationCode`
     - **SECURITY_QUESTIONS:** Valida la respuesta contra `SecurityQuestion`
     - **TOTP:** Valida el token usando `TOTPDevice`
     - **USB_KEY:** Valida el token FIDO/U2F

4. **Si la validación es exitosa:**
   - Termina cualquier sesión activa previa (`User.terminateActiveSession()`)
   - Crea una nueva sesión (`Session`)
   - Realiza login de Django
   - Resetea contadores de intentos fallidos
   - Redirige a la pantalla de Login (o dashboard)

5. **Si la validación falla:**
   - Muestra mensaje de error
   - Permite reintentar

### Requisitos Cumplidos
- ✅ **RS2 F2.4:** Ejecución de MFA según el tipo (código, preguntas, USB)
- ✅ **RS2 F2.5:** Validación final de MFA usando `User.validateMFA()` o `MFAMethod.validate()`
- ✅ **RS5 F5.3:** Control de sesión única (termina sesión anterior)
- ✅ **RS7 F7.1:** Creación de sesión de trabajo

### Próximo Paso
El usuario queda autenticado y puede acceder al sistema.

---

## 5. Pantalla de Recuperación de Contraseña

**URL:** `/recover/` y `/recover/reset/`  
**Método:** GET, POST  
**Requisito del Sistema:** RS4 - Recuperación de Usuario/Contraseña

### Funcionalidad
Permite a los usuarios recuperar su contraseña olvidada mediante un código enviado a su correo electrónico.

### Pantalla 1: Solicitud de Recuperación

**Campos del Formulario:**
- **email** (email, requerido): Correo electrónico del usuario

**Flujo:**
1. Usuario ingresa su email
2. Sistema busca el usuario por email
3. Si existe, llama a `User.requestPasswordReset()`
4. Sistema genera código de recuperación
5. Sistema envía código al correo del usuario
6. Registra intento de reseteo en `AccessAttempt`
7. Muestra formulario para ingresar código y nueva contraseña

### Pantalla 2: Reseteo de Contraseña

**Campos del Formulario:**
- **code** (texto, requerido, 6 dígitos): Código de recuperación recibido
- **new_password** (contraseña, requerido): Nueva contraseña
- **confirm_password** (contraseña, requerido): Confirmación de nueva contraseña

**Flujo:**
1. Usuario ingresa código, nueva contraseña y confirmación
2. Sistema valida que las contraseñas coincidan
3. Sistema llama a `User.validatePasswordReset(code, new_password)`
4. Sistema valida el código usando `AccountRecovery.verifyCode()`
5. Si el código es válido:
   - Actualiza la contraseña del usuario
   - Marca el `AccountRecovery` como completado
   - Registra reseteo exitoso en `AccessAttempt`
   - Redirige a Login
6. Si el código es inválido o expirado:
   - Muestra mensaje de error

### Requisitos Cumplidos
- ✅ **RS4 F4.1:** Formulario de solicitud de recuperación
- ✅ **RS4 F4.2:** Inicio de proceso con `User.requestPasswordReset()`
- ✅ **RS4 F4.3:** Generación de código con `AccountRecovery.generateCode()`
- ✅ **RS4 F4.4:** Envío de notificación con `AccountRecovery.sendNotification()`
- ✅ **RS4 F4.5:** Formulario de reseteo
- ✅ **RS4 F4.6:** Validación y cambio con `User.validatePasswordReset()`
- ✅ **RS3 F3.3:** Registro de intentos de reseteo

### Próximo Paso
El usuario puede ir a la pantalla de **Login** con su nueva contraseña.

---

## 6. Pantalla de Desbloqueo de Cuenta

**URL:** `/unlock/`  
**Método:** GET, POST  
**Requisito del Sistema:** RS6 - Control de Intentos Fallidos y Bloqueo

### Funcionalidad
Permite a los usuarios desbloquear su cuenta cuando ha sido bloqueada por múltiples intentos fallidos de login.

### Campos del Formulario
- **username** (texto, requerido): Username del usuario
- **code** (texto, opcional, 6 dígitos): Código de desbloqueo recibido

### Flujo de Funcionamiento

#### Paso 1: Solicitar Código de Desbloqueo

1. **Usuario ingresa su username:**
   - Ingresa el username de la cuenta bloqueada
   - Deja el campo `code` vacío

2. **Sistema procesa la solicitud:**
   - Busca el usuario por username
   - Crea un registro `AccountUnlock`
   - Genera código de desbloqueo de 6 dígitos
   - Establece expiración de 30 minutos
   - Envía código al correo del usuario
   - Registra intento de desbloqueo en `AccessAttempt`

3. **Usuario recibe el código:**
   - Recibe email con código de desbloqueo

#### Paso 2: Verificar Código y Desbloquear

1. **Usuario ingresa código:**
   - Ingresa el username
   - Ingresa el código de desbloqueo recibido

2. **Sistema valida y desbloquea:**
   - Llama a `User.unlock(code)`
   - Sistema valida el código usando `AccountUnlock.verifyCode()`
   - Si el código es válido:
     - Establece `is_locked=False`
     - Limpia `locked_until`
     - Resetea `failed_login_attempts` a 0
     - Marca el `AccountUnlock` como completado
     - Registra desbloqueo exitoso en `AccessAttempt`
     - Redirige a Login
   - Si el código es inválido o expirado:
     - Muestra mensaje de error

### Requisitos Cumplidos
- ✅ **RS6 F6.5:** Proceso de desbloqueo iniciado por el usuario
- ✅ **RS6 F6.6:** Gestión de desbloqueo con `AccountUnlock.generateCode()` y `sendNotification()`
- ✅ **RS6 F6.7:** Validación de desbloqueo con `User.unlock(code)`
- ✅ **RS3 F3.3:** Registro de intentos de desbloqueo

### Próximo Paso
El usuario puede ir a la pantalla de **Login** para iniciar sesión nuevamente.

---

## 7. Pantalla de Logout

**URL:** `/logout/`  
**Método:** GET, POST (requiere autenticación)  
**Requisito del Sistema:** RS7 - Gestión de Sesión de Trabajo

### Funcionalidad
Permite a los usuarios cerrar sesión de forma segura, terminando su sesión activa en el sistema.

### Flujo de Funcionamiento

1. **Usuario hace clic en "Salir":**
   - Accede a la URL `/logout/` o hace clic en el enlace de logout

2. **Sistema termina la sesión:**
   - Obtiene el ID de la sesión personalizada desde la sesión de Django
   - Llama a `Session.terminate()` que:
     - Establece `is_active=False`
     - Establece `terminated_at` con la fecha/hora actual
   - Registra el logout en `AccessAttempt`
   - Ejecuta `logout()` de Django para cerrar la sesión HTTP

3. **Usuario es redirigido:**
   - Redirigido a la pantalla de Login
   - Ya no tiene acceso a recursos protegidos

### Requisitos Cumplidos
- ✅ **RS7 F7.4:** Cierre de sesión con `Session.terminate()`
- ✅ **RS3:** Registro de logout en `AccessAttempt`

### Próximo Paso
El usuario debe iniciar sesión nuevamente para acceder al sistema.

---

## Flujos Completos del Sistema

### Flujo 1: Registro y Activación de Nuevo Usuario
```
1. Usuario → /register/ (completa formulario)
2. Sistema → Genera username y contraseña temporal
3. Sistema → Envía código de activación
4. Usuario → /activate/ (ingresa código)
5. Sistema → Activa cuenta
6. Usuario → /login/ (inicia sesión)
```

### Flujo 2: Login con MFA
```
1. Usuario → /login/ (ingresa credenciales)
2. Sistema → Valida username/password
3. Sistema → Detecta método MFA
4. Sistema → Envía código MFA
5. Usuario → /mfa/ (ingresa código MFA)
6. Sistema → Valida MFA
7. Sistema → Crea sesión y autentica usuario
```

### Flujo 3: Recuperación de Contraseña
```
1. Usuario → /recover/ (ingresa email)
2. Sistema → Envía código de recuperación
3. Usuario → /recover/ (ingresa código y nueva contraseña)
4. Sistema → Valida código y actualiza contraseña
5. Usuario → /login/ (inicia sesión con nueva contraseña)
```

### Flujo 4: Desbloqueo de Cuenta
```
1. Usuario → /unlock/ (ingresa username)
2. Sistema → Envía código de desbloqueo
3. Usuario → /unlock/ (ingresa código)
4. Sistema → Valida código y desbloquea cuenta
5. Usuario → /login/ (inicia sesión)
```

### Flujo 5: Bloqueo por Intentos Fallidos
```
1. Usuario → /login/ (intenta login con credenciales incorrectas)
2. Sistema → Registra intento fallido
3. Sistema → Cuenta intentos fallidos (máximo 4 en 15 minutos)
4. Sistema → Bloquea cuenta automáticamente
5. Usuario → /unlock/ (solicita desbloqueo)
```

---

## Modelos y Métodos Utilizados

### Modelo: CustomUser
- `activate(code)` - Activa la cuenta con código
- `addMFADevice(method_type)` - Añade método MFA
- `validateMFA(mfa_id, code)` - Valida código MFA
- `logAttempt(...)` - Registra intento de acceso
- `requestPasswordReset()` - Inicia recuperación de contraseña
- `validatePasswordReset(code, new_password)` - Valida y cambia contraseña
- `deactivate()` - Desactiva cuenta
- `reactivate()` - Reactiva cuenta
- `terminateActiveSession()` - Termina sesión activa
- `checkFailedAttempts()` - Cuenta intentos fallidos
- `lock()` - Bloquea cuenta
- `unlock(code)` - Desbloquea cuenta

### Modelo: MFAMethod
- `generateCode()` - Genera código de verificación
- `sendNotification()` - Envía código al usuario
- `validate(input_value)` - Valida código/respuesta
- `enable()` - Habilita método MFA
- `disable()` - Deshabilita método MFA

### Modelo: AccessAttempt
- `create(...)` - Crea registro de intento

### Modelo: AccountRecovery
- `generateCode()` - Genera código de recuperación
- `sendNotification()` - Envía código al correo
- `verifyCode(code)` - Verifica código

### Modelo: AccountUnlock
- `generateCode()` - Genera código de desbloqueo
- `sendNotification()` - Envía código al correo
- `verifyCode(code)` - Verifica código

### Modelo: Session
- `updateLastActivity()` - Actualiza última actividad
- `isExpired()` - Verifica si expiró
- `terminate()` - Termina la sesión

---

## Notas Técnicas

### Seguridad
- Todos los códigos tienen tiempo de expiración (10-30 minutos)
- Los códigos se invalidan después de ser usados
- Las contraseñas se almacenan como hash (Django)
- Las sesiones se invalidan al hacer logout
- Control de sesión única (una sesión activa por usuario)

### Auditoría
- Todos los eventos se registran en `AccessAttempt`:
  - Creación de usuarios
  - Intentos de login (exitosos y fallidos)
  - Reseteo de contraseña
  - Desbloqueo de cuenta
- Se registra IP y dispositivo en cada intento

### Configuración
- Los emails se envían a la consola en desarrollo (configurar SMTP para producción)
- Los SMS se simulan en consola (integrar servicio SMS para producción)
- Las sesiones expiran después de 2 horas de inactividad
- Máximo 4 intentos fallidos antes de bloquear cuenta

---

## Contacto y Soporte

Para más información sobre la implementación, consultar:
- `accounts/models.py` - Modelos del sistema
- `accounts/views.py` - Lógica de las vistas
- `accounts/urls.py` - Rutas del sistema
- `templates/accounts/` - Plantillas HTML

