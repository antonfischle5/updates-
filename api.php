<?php
declare(strict_types=1);

/*
 * PHP replacement for the former Node.js authentication API.
 * Requires PHP with PDO_SQLITE enabled. Keep data/ and private-files/ protected.
 */
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin');

function respond(int $status, array $body = []): never {
    http_response_code($status);
    echo json_encode($body, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

$isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');

session_name('auth_sid');
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => $isHttps,
    'httponly' => true,
    'samesite' => 'Strict',
]);
ini_set('session.use_strict_mode', '1');
session_start();

$action = (string)($_GET['action'] ?? '');
$method = (string)($_SERVER['REQUEST_METHOD'] ?? 'GET');

if (in_array($action, ['register', 'login', 'logout', 'update-profile', 'admin-permissions', 'admin-user-action'], true) && $method === 'POST') {
    $origin = (string)($_SERVER['HTTP_ORIGIN'] ?? '');
    if ($origin !== '') {
        $originParts = parse_url($origin);
        $requestHost = strtolower((string)($_SERVER['HTTP_HOST'] ?? ''));
        $originHost = strtolower((string)($originParts['host'] ?? ''));
        $originScheme = strtolower((string)($originParts['scheme'] ?? ''));
        $expectedScheme = $isHttps ? 'https' : 'http';
        if ($originHost === '' || $originHost !== preg_replace('/:\\d+$/', '', $requestHost)
            || $originScheme !== $expectedScheme) {
            respond(403, ['error' => 'Ungültige Herkunft der Anfrage.']);
        }
    }
}

$dataDir = __DIR__ . DIRECTORY_SEPARATOR . 'data';
if (!is_dir($dataDir) && !@mkdir($dataDir, 0700, true) && !is_dir($dataDir)) {
    respond(500, ['error' => 'Der geschützte Datenordner konnte nicht erstellt werden.']);
}
if (!is_writable($dataDir)) {
    respond(500, ['error' => 'Der Datenordner ist nicht beschreibbar. Bitte prüfe die Ordnerrechte.']);
}
if (!extension_loaded('pdo_sqlite')) {
    respond(500, ['error' => 'Auf diesem Webspace ist PDO_SQLITE nicht verfügbar. Bitte aktiviere SQLite-Unterstützung oder nutze eine unterstützte Datenbank.']);
}

try {
    $db = new PDO('sqlite:' . $dataDir . DIRECTORY_SEPARATOR . 'users.sqlite', null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_TIMEOUT => 5,
    ]);
    $db->exec('PRAGMA busy_timeout = 5000');
    $db->exec('CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        username_key TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )');
    $db->exec('CREATE TABLE IF NOT EXISTS module_permissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username_key TEXT NOT NULL,
        module TEXT NOT NULL,
        allowed INTEGER NOT NULL DEFAULT 1,
        UNIQUE(username_key, module)
    )');
    $db->exec('CREATE TABLE IF NOT EXISTS auth_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_key TEXT NOT NULL,
        attempted_at INTEGER NOT NULL
    )');
    $db->exec('CREATE TABLE IF NOT EXISTS banned_ips (
        ip_key TEXT PRIMARY KEY,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )');
    $userColumns = $db->query('PRAGMA table_info(users)')->fetchAll();
    $columnNames = array_column($userColumns, 'name');
    if (!in_array('is_banned', $columnNames, true)) {
        $db->exec('ALTER TABLE users ADD COLUMN is_banned INTEGER NOT NULL DEFAULT 0');
    }
    if (!in_array('last_ip_key', $columnNames, true)) {
        $db->exec('ALTER TABLE users ADD COLUMN last_ip_key TEXT');
    }
    if (!in_array('is_admin', $columnNames, true)) {
        $db->exec('ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0');
    }
    // Der bisherige Hauptadministrator bleibt Administrator, auch bei einer bestehenden Datenbank.
    $db->prepare('UPDATE users SET is_admin = 1 WHERE username_key = ?')->execute(['antonfischle']);
} catch (Throwable $error) {
    error_log('Auth database setup failed: ' . $error->getMessage());
    respond(500, ['error' => 'Die Datenbank konnte nicht geöffnet werden. Prüfe die SQLite-Unterstützung und die Ordnerrechte.']);
}

function isAdmin(): bool {
    global $db;
    if (empty($_SESSION['user_id'])) return false;
    $stmt = $db->prepare('SELECT username_key, is_admin FROM users WHERE id = ?');
    $stmt->execute([(int)$_SESSION['user_id']]);
    $user = $stmt->fetch();
    if (!$user) return false;
    return (int)($user['is_admin'] ?? 0) === 1 || strtolower((string)$user['username_key']) === 'antonfischle';
}
function requireAdmin(): void {
    requireLogin();
    if (!isAdmin()) respond(403, ['error' => 'Nur Administratoren dürfen diese Funktion verwenden.']);
}
function requireLogin(): void {
    global $db;
    if (empty($_SESSION['user_id'])) {
        respond(401, ['error' => 'Bitte melde dich zuerst an.']);
    }
    $stmt = $db->prepare('SELECT is_banned FROM users WHERE id = ?');
    $stmt->execute([(int)$_SESSION['user_id']]);
    $isBanned = $stmt->fetchColumn();
    if ($isBanned === false || (int)$isBanned === 1) {
        $_SESSION = [];
        session_destroy();
        respond(403, ['error' => 'Dieses Benutzerkonto wurde gesperrt.']);
    }
    if (ipIsBanned($db, currentIpKey())) {
        $_SESSION = [];
        session_destroy();
        respond(403, ['error' => 'Diese IP-Adresse wurde gesperrt.']);
    }
}
function currentIpKey(): string {
    return hash('sha256', (string)($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
}
function ipIsBanned(PDO $db, string $ipKey): bool {
    $stmt = $db->prepare('SELECT 1 FROM banned_ips WHERE ip_key = ?');
    $stmt->execute([$ipKey]);
    return (bool)$stmt->fetchColumn();
}

if ($action === 'register' || $action === 'login') {
    if ($method !== 'POST') {
        header('Allow: POST');
        respond(405, ['error' => 'Diese Anfrage ist nicht erlaubt.']);
    }

    $ip = (string)($_SERVER['REMOTE_ADDR'] ?? 'unknown');
    $ipKey = hash('sha256', $ip);
    if (ipIsBanned($db, $ipKey)) {
        respond(403, ['error' => 'Diese IP-Adresse wurde gesperrt.']);
    }
    $cutoff = time() - 900;
    try {
        $db->prepare('DELETE FROM auth_attempts WHERE attempted_at < ?')->execute([$cutoff]);
        $countStmt = $db->prepare('SELECT COUNT(*) FROM auth_attempts WHERE ip_key = ? AND attempted_at >= ?');
        $countStmt->execute([$ipKey, $cutoff]);
        if ((int)$countStmt->fetchColumn() >= 10) {
            respond(429, ['error' => 'Zu viele Versuche. Bitte warte 15 Minuten.']);
        }
        $db->prepare('INSERT INTO auth_attempts (ip_key, attempted_at) VALUES (?, ?)')->execute([$ipKey, time()]);
    } catch (Throwable $error) {
        error_log('Auth rate limit failed: ' . $error->getMessage());
        respond(500, ['error' => 'Die Anmeldung ist vorübergehend nicht verfügbar.']);
    }

    $raw = file_get_contents('php://input');
    $body = json_decode($raw === false ? '' : $raw, true);
    if (!is_array($body)) {
        respond(400, ['error' => 'Ungültige Anfrage.']);
    }

    $username = is_string($body['username'] ?? null) ? trim($body['username']) : '';
    $password = is_string($body['password'] ?? null) ? $body['password'] : '';
    if (!preg_match('/^[a-zA-Z0-9_-]{3,32}$/', $username)) {
        respond(400, ['error' => 'Benutzername: 3–32 Zeichen, nur Buchstaben, Zahlen, _ und -.']);
    }
    if ($action === 'register' && strtolower($username) === 'antonfischle') {
        respond(403, ['error' => 'Dieser Benutzername ist reserviert.']);
    }
    if (strlen($password) < 6 || strlen($password) > 100) {
        respond(400, ['error' => 'Das Passwort muss zwischen 6 und 100 Zeichen lang sein.']);
    }

    if ($action === 'register') {
        $algo = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT;
        if ($algo === PASSWORD_DEFAULT && strlen($password) > 72) {
            respond(400, ['error' => 'Dieses PHP-System unterstützt kein Argon2id. Bitte verwende für dieses Konto ein Passwort mit höchstens 72 Bytes.']);
        }
        $hash = password_hash($password, $algo);
        try {
            $stmt = $db->prepare('INSERT INTO users (username, username_key, password_hash, last_ip_key) VALUES (?, ?, ?, ?)');
            $stmt->execute([$username, strtolower($username), $hash, $ipKey]);
            $userId = (int)$db->lastInsertId();
        } catch (PDOException $error) {
            if (str_contains(strtolower($error->getMessage()), 'unique')) {
                respond(409, ['error' => 'Dieser Benutzername ist bereits vergeben.']);
            }
            error_log('User registration failed: ' . $error->getMessage());
            respond(500, ['error' => 'Das Konto konnte nicht erstellt werden.']);
        }

        session_regenerate_id(true);
        $_SESSION['user_id'] = $userId;
        $_SESSION['username'] = $username;
        respond(201, ['username' => $username]);
    }

    $stmt = $db->prepare('SELECT id, username, password_hash, is_banned FROM users WHERE username_key = ?');
    $stmt->execute([strtolower($username)]);
    $user = $stmt->fetch();
    if (!$user || !password_verify($password, (string)$user['password_hash'])) {
        respond(401, ['error' => 'Benutzername oder Passwort ist falsch.']);
    }
    if ((int)$user['is_banned'] === 1) {
        respond(403, ['error' => 'Dieses Benutzerkonto wurde gesperrt.']);
    }
    if (ipIsBanned($db, $ipKey)) {
        respond(403, ['error' => 'Diese IP-Adresse wurde gesperrt.']);
    }
    $db->prepare('UPDATE users SET last_ip_key = ? WHERE id = ?')->execute([$ipKey, (int)$user['id']]);
    session_regenerate_id(true);
    $_SESSION['user_id'] = (int)$user['id'];
    $_SESSION['username'] = (string)$user['username'];
    respond(200, ['username' => (string)$user['username']]);
}

if ($action === 'me') {
    if ($method !== 'GET') respond(405, ['error' => 'Diese Anfrage ist nicht erlaubt.']);
    requireLogin();
    respond(200, ['username' => (string)($_SESSION['username'] ?? '')]);
}

if ($action === 'logout') {
    if ($method !== 'POST') respond(405, ['error' => 'Diese Anfrage ist nicht erlaubt.']);
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', [
            'expires' => time() - 42000,
            'path' => $params['path'],
            'secure' => $params['secure'],
            'httponly' => $params['httponly'],
            'samesite' => 'Strict',
        ]);
    }
    session_destroy();
    http_response_code(204);
    exit;
}

if ($action === 'update-profile') {
    if ($method !== 'POST') {
        header('Allow: POST');
        respond(405, ['error' => 'Diese Anfrage ist nicht erlaubt.']);
    }
    requireLogin();

    $raw = file_get_contents('php://input');
    $body = json_decode($raw === false ? '' : $raw, true);
    if (!is_array($body)) respond(400, ['error' => 'Ungültige Anfrage.']);

    $currentPassword = is_string($body['currentPassword'] ?? null) ? $body['currentPassword'] : '';
    $newUsername = array_key_exists('username', $body) && is_string($body['username']) ? trim($body['username']) : null;
    $newPassword = is_string($body['newPassword'] ?? null) ? $body['newPassword'] : '';

    if ($currentPassword === '') respond(400, ['error' => 'Bitte gib dein aktuelles Passwort ein.']);

    $stmt = $db->prepare('SELECT id, username, password_hash FROM users WHERE id = ?');
    $stmt->execute([(int)$_SESSION['user_id']]);
    $user = $stmt->fetch();
    if (!$user || !password_verify($currentPassword, (string)$user['password_hash'])) {
        respond(403, ['error' => 'Dein aktuelles Passwort ist falsch.']);
    }

    if ($newUsername !== null) {
        if (!preg_match('/^[a-zA-Z0-9_-]{3,32}$/', $newUsername)) {
            respond(400, ['error' => 'Der Name muss 3–32 Zeichen lang sein und darf nur Buchstaben, Zahlen, _ und - enthalten.']);
        }
        if (strtolower($newUsername) === 'antonfischle' && !isAdmin()) {
            respond(403, ['error' => 'Dieser Benutzername ist reserviert.']);
        }
        try {
            $stmt = $db->prepare('UPDATE users SET username = ?, username_key = ? WHERE id = ?');
            $stmt->execute([$newUsername, strtolower($newUsername), (int)$_SESSION['user_id']]);
        } catch (PDOException $error) {
            if (str_contains(strtolower($error->getMessage()), 'unique')) {
                respond(409, ['error' => 'Dieser Name wird bereits verwendet. Bitte wähle einen anderen.']);
            }
            error_log('Username update failed: ' . $error->getMessage());
            respond(500, ['error' => 'Der Name konnte nicht geändert werden.']);
        }
        $_SESSION['username'] = $newUsername;
    }

    if ($newPassword !== '') {
        if (strlen($newPassword) < 6 || strlen($newPassword) > 100) {
            respond(400, ['error' => 'Das neue Passwort muss zwischen 6 und 100 Zeichen lang sein.']);
        }
        $algo = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT;
        if ($algo === PASSWORD_DEFAULT && strlen($newPassword) > 72) {
            respond(400, ['error' => 'Das neue Passwort ist für diese PHP-Konfiguration zu lang.']);
        }
        $hash = password_hash($newPassword, $algo);
        $stmt = $db->prepare('UPDATE users SET password_hash = ? WHERE id = ?');
        $stmt->execute([$hash, (int)$_SESSION['user_id']]);
    }

    respond(200, ['username' => (string)($_SESSION['username'] ?? '')]);
}


if ($action === 'admin-info') {
    if ($method !== 'GET') respond(405, ['error' => 'Diese Anfrage ist nicht erlaubt.']);
    requireLogin();
    respond(200, ['isAdmin' => isAdmin(), 'username' => (string)($_SESSION['username'] ?? '')]);
}

if ($action === 'admin-users') {
    if ($method !== 'GET') respond(405, ['error' => 'Diese Anfrage ist nicht erlaubt.']);
    requireAdmin();
    $rows = $db->query('SELECT username, is_banned, is_admin FROM users ORDER BY username COLLATE NOCASE')->fetchAll();
    $users = array_map(static fn(array $row): array => ['username' => (string)$row['username'], 'banned' => (int)$row['is_banned'] === 1, 'isAdmin' => (int)$row['is_admin'] === 1], $rows);
    respond(200, ['users' => $users, 'userCount' => count($users), 'modules' => ['files' => 'Dateien', 'activity' => 'Aktivität']]);
}

if ($action === 'admin-user-action') {
    if ($method !== 'POST') respond(405, ['error' => 'Diese Anfrage ist nicht erlaubt.']);
    requireAdmin();
    $raw = file_get_contents('php://input');
    $body = json_decode($raw === false ? '' : $raw, true);
    if (!is_array($body)) respond(400, ['error' => 'Ungültige Anfrage.']);
    $username = is_string($body['username'] ?? null) ? trim($body['username']) : '';
    $operation = (string)($body['operation'] ?? '');
    if (!preg_match('/^[a-zA-Z0-9_-]{3,32}$/', $username)) respond(400, ['error' => 'Ungültiger Benutzername.']);
    if (!in_array($operation, ['ban', 'unban', 'ipban', 'ipunban', 'make-admin', 'remove-admin'], true)) respond(400, ['error' => 'Unbekannte Aktion.']);
    if (in_array($operation, ['ban', 'unban', 'ipban', 'ipunban'], true) && strtolower($username) === strtolower((string)($_SESSION['username'] ?? ''))) {
        respond(400, ['error' => 'Du kannst dein eigenes Administratorkonto nicht sperren.']);
    }
    if ($operation === 'remove-admin' && strtolower($username) === 'antonfischle') {
        respond(403, ['error' => 'Die Adminrechte des Hauptadministrators können nicht entfernt werden.']);
    }
    if ($operation === 'remove-admin' && strtolower($username) === strtolower((string)($_SESSION['username'] ?? ''))) {
        respond(400, ['error' => 'Du kannst dir deine eigenen Adminrechte nicht entziehen.']);
    }
    $stmt = $db->prepare('SELECT id, username, is_banned, last_ip_key, is_admin FROM users WHERE username_key = ?');
    $stmt->execute([strtolower($username)]);
    $target = $stmt->fetch();
    if (!$target) respond(404, ['error' => 'Benutzer nicht gefunden.']);
    if (in_array($operation, ['ban', 'unban', 'ipban', 'ipunban'], true) && strtolower((string)$target['username']) === 'antonfischle') respond(403, ['error' => 'Das Hauptadministratorkonto kann nicht gesperrt werden.']);
    try {
        if ($operation === 'make-admin' || $operation === 'remove-admin') {
            $db->prepare('UPDATE users SET is_admin = ? WHERE id = ?')->execute([$operation === 'make-admin' ? 1 : 0, (int)$target['id']]);
        } elseif ($operation === 'ban' || $operation === 'unban') {
            $db->prepare('UPDATE users SET is_banned = ? WHERE id = ?')->execute([$operation === 'ban' ? 1 : 0, (int)$target['id']]);
        } else {
            $ipKey = (string)($target['last_ip_key'] ?? '');
            if ($ipKey === '') respond(400, ['error' => 'Für diesen Benutzer ist noch keine IP-Adresse gespeichert. Der Benutzer muss sich erst anmelden.']);
            if ($operation === 'ipban' && $ipKey === currentIpKey()) {
                respond(400, ['error' => 'Diese IP-Adresse ist auch deine aktuelle Admin-IP. Der Bann wurde zum Schutz deines Zugangs abgebrochen.']);
            }
            if ($operation === 'ipban') {
                $db->prepare('INSERT OR IGNORE INTO banned_ips (ip_key) VALUES (?)')->execute([$ipKey]);
            } else {
                $db->prepare('DELETE FROM banned_ips WHERE ip_key = ?')->execute([$ipKey]);
            }
        }
    } catch (Throwable $error) {
        error_log('Admin user action failed: ' . $error->getMessage());
        respond(500, ['error' => 'Die Aktion konnte nicht gespeichert werden.']);
    }
    respond(200, ['ok' => true, 'operation' => $operation, 'username' => (string)$target['username']]);
}

if ($action === 'admin-permissions') {
    if ($method !== 'GET' && $method !== 'POST') respond(405, ['error' => 'Diese Anfrage ist nicht erlaubt.']);
    requireAdmin();
    if ($method === 'GET') {
        $rows = $db->query('SELECT username_key, module, allowed FROM module_permissions')->fetchAll();
        respond(200, ['permissions' => $rows]);
    }
    $raw = file_get_contents('php://input');
    $body = json_decode($raw === false ? '' : $raw, true);
    if (!is_array($body)) respond(400, ['error' => 'Ungültige Anfrage.']);
    $scope = (string)($body['scope'] ?? '');
    $username = is_string($body['username'] ?? null) ? trim($body['username']) : '';
    $module = (string)($body['module'] ?? '');
    $allowed = ($body['allowed'] ?? null) === true ? 1 : 0;
    if (!in_array($module, ['files', 'activity'], true)) respond(400, ['error' => 'Unbekanntes Modul.']);
    if (!in_array($scope, ['all', 'user'], true)) respond(400, ['error' => 'Ungültiger Geltungsbereich.']);
    if ($scope === 'user' && !preg_match('/^[a-zA-Z0-9_-]{3,32}$/', $username)) respond(400, ['error' => 'Bitte wähle einen gültigen Benutzer.']);
    try {
        if ($scope === 'all') {
            $db->prepare('DELETE FROM module_permissions WHERE username_key = ? AND module = ?')->execute(['*', $module]);
            $stmt = $db->prepare('INSERT INTO module_permissions (username_key, module, allowed) VALUES (?, ?, ?)');
            $stmt->execute(['*', $module, $allowed]);
        } else {
            $stmt = $db->prepare('INSERT INTO module_permissions (username_key, module, allowed) VALUES (?, ?, ?) ON CONFLICT(username_key, module) DO UPDATE SET allowed = excluded.allowed');
            $stmt->execute([strtolower($username), $module, $allowed]);
        }
    } catch (Throwable $error) {
        error_log('Admin permission update failed: ' . $error->getMessage());
        respond(500, ['error' => 'Berechtigung konnte nicht gespeichert werden.']);
    }
    respond(200, ['ok' => true]);
}

if ($action === 'module-access') {
    if ($method !== 'GET') respond(405, ['error' => 'Diese Anfrage ist nicht erlaubt.']);
    requireLogin();
    $usernameKey = strtolower((string)($_SESSION['username'] ?? ''));
    if (isAdmin()) respond(200, ['access' => ['files' => true, 'activity' => true]]);
    $stmt = $db->prepare("SELECT module, allowed FROM module_permissions WHERE username_key IN ('*', ?) ORDER BY username_key");
    $stmt->execute([$usernameKey]);
    $access = ['files' => true, 'activity' => true];
    foreach ($stmt->fetchAll() as $row) {
        $access[(string)$row['module']] = (int)$row['allowed'] === 1;
    }
    respond(200, ['access' => $access]);
}

if ($action === 'files') {
    if ($method !== 'GET') respond(405, ['error' => 'Diese Anfrage ist nicht erlaubt.']);
    requireLogin();
    if (!moduleAllowed($db, 'files')) respond(403, ['error' => 'Der Administrator hat den Zugriff auf dieses Modul gesperrt.']);
    respond(200, [['id' => 'welcome', 'name' => 'Willkommen.txt']]);
}

function moduleAllowed(PDO $db, string $module): bool {
    if (isAdmin()) return true;
    $usernameKey = strtolower((string)($_SESSION['username'] ?? ''));
    $stmt = $db->prepare("SELECT username_key, allowed FROM module_permissions WHERE module = ? AND username_key IN ('*', ?) ORDER BY username_key");
    $stmt->execute([$module, $usernameKey]);
    $allowed = true;
    foreach ($stmt->fetchAll() as $row) $allowed = (int)$row['allowed'] === 1;
    return $allowed;
}

if ($action === 'file') {
    if ($method !== 'GET') respond(405, ['error' => 'Diese Anfrage ist nicht erlaubt.']);
    requireLogin();
    if (!moduleAllowed($db, 'files')) respond(403, ['error' => 'Der Administrator hat den Zugriff auf dieses Modul gesperrt.']);
    $id = (string)($_GET['id'] ?? '');
    if ($id !== 'welcome') respond(404, ['error' => 'Datei nicht gefunden.']);
    $filePath = __DIR__ . DIRECTORY_SEPARATOR . 'private-files' . DIRECTORY_SEPARATOR . 'welcome.txt';
    if (!is_file($filePath) || !is_readable($filePath)) {
        respond(404, ['error' => 'Datei nicht gefunden.']);
    }
    header('Content-Type: text/plain; charset=utf-8');
    echo file_get_contents($filePath);
    exit;
}

respond(404, ['error' => 'Nicht gefunden.']);
