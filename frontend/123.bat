@echo off
setlocal

REM Creates folders and empty files in the current directory
REM Run this inside the frontend directory

if not exist "src" (
    echo This script must be run inside the frontend project directory.
    exit /b 1
)

REM Directories
mkdir src\api 2>nul
mkdir src\crypto 2>nul
mkdir src\components 2>nul
mkdir src\pages 2>nul
mkdir src\store 2>nul
mkdir src\utils 2>nul
mkdir src\types 2>nul
mkdir public\assets 2>nul

REM API files
type nul > src\api\auth.ts
type nul > src\api\messages.ts
type nul > src\api\contacts.ts
type nul > src\api\admin.ts
type nul > src\api\client.ts

REM Crypto files
type nul > src\crypto\base64.ts
type nul > src\crypto\keys.ts
type nul > src\crypto\messages.ts
type nul > src\crypto\attachments.ts
type nul > src\crypto\storage.ts

REM Component files
type nul > src\components\AuthForm.tsx
type nul > src\components\ContactList.tsx
type nul > src\components\ChatWindow.tsx
type nul > src\components\MessageComposer.tsx
type nul > src\components\AttachmentButton.tsx
type nul > src\components\AdminUserTable.tsx
type nul > src\components\Layout.tsx

REM Page files
type nul > src\pages\LoginPage.tsx
type nul > src\pages\RegisterPage.tsx
type nul > src\pages\ChatPage.tsx
type nul > src\pages\AdminPage.tsx
type nul > src\pages\NotFoundPage.tsx

REM Store files
type nul > src\store\authStore.ts
type nul > src\store\chatStore.ts

REM Utility files
type nul > src\utils\time.ts
type nul > src\utils\validators.ts
type nul > src\utils\constants.ts

REM Type files
type nul > src\types\auth.ts
type nul > src\types\message.ts
type nul > src\types\contact.ts
type nul > src\types\api.ts

REM Root app files
type nul > src\App.tsx
type nul > src\main.tsx
type nul > src\router.tsx
type nul > src\env.d.ts

echo Frontend folders and files created successfully.
endlocal