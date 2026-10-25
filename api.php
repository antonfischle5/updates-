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
    $db->exec('CREATE TABLE IF NOT EXISTS user_profiles (user_id INTEGER PRIMARY KEY, bio TEXT NOT NULL DEFAULT \'\', avatar_url TEXT NOT NULL DEFAULT \'\', FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)');
    $db->exec('CREATE TABLE IF NOT EXISTS clicker_scores (
        user_id INTEGER PRIMARY KEY, score INTEGER NOT NULL DEFAULT 0, power INTEGER NOT NULL DEFAULT 1, upgrade_cost INTEGER NOT NULL DEFAULT 25,
        auto_clicks INTEGER NOT NULL DEFAULT 0, auto_cost INTEGER NOT NULL DEFAULT 100, multiplier INTEGER NOT NULL DEFAULT 1,
        multiplier_cost INTEGER NOT NULL DEFAULT 250, super_bonus INTEGER NOT NULL DEFAULT 0, super_cost INTEGER NOT NULL DEFAULT 1000,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )');
    $clickerColumns = $db->query('PRAGMA table_info(clicker_scores)')->fetchAll();
    $clickerColumnNames = array_column($clickerColumns, 'name');
    foreach (['auto_clicks' => 'INTEGER NOT NULL DEFAULT 0', 'auto_cost' => 'INTEGER NOT NULL DEFAULT 100', 'multiplier' => 'INTEGER NOT NULL DEFAULT 1', 'multiplier_cost' => 'INTEGER NOT NULL DEFAULT 250', 'super_bonus' => 'INTEGER NOT NULL DEFAULT 0', 'super_cost' => 'INTEGER NOT NULL DEFAULT 1000'] as $column => $definition) {
        if (!in_array($column, $clickerColumnNames, true)) $db->exec('ALTER TABLE clicker_scores ADD COLUMN ' . $column . ' ' . $definition);
    }
    $db->exec('CREATE TABLE IF NOT EXISTS farming_state (user_id INTEGER PRIMARY KEY, coins INTEGER NOT NULL DEFAULT 100, total_earned INTEGER NOT NULL DEFAULT 0, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)');
    $db->exec("CREATE TABLE IF NOT EXISTS farming_workers (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, crop_key TEXT NOT NULL DEFAULT 'wheat', started_at INTEGER NOT NULL, duration INTEGER NOT NULL, reward INTEGER NOT NULL, claimed INTEGER NOT NULL DEFAULT 0, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)");
    $db->exec('CREATE TABLE IF NOT EXISTS user_badges (
        user_id INTEGER NOT NULL, badge_key TEXT NOT NULL, awarded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY(user_id, badge_key), FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
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


if ($action === 'farming-state') {
    if (!moduleAllowed($db, 'farming')) respond(403, ['error' => 'Dieses Spiel wurde vom Administrator gesperrt.']);
 requireLogin();$uid=(int)$_SESSION['user_id'];$db->prepare('INSERT OR IGNORE INTO farming_state(user_id) VALUES(?)')->execute([$uid]);$s=$db->prepare('SELECT coins,total_earned FROM farming_state WHERE user_id=?');$s->execute([$uid]);$w=$db->prepare('SELECT id,crop_key,started_at,duration,reward,claimed FROM farming_workers WHERE user_id=? ORDER BY id');$w->execute([$uid]);$workers=[];foreach($w->fetchAll() as $x){$x['ready']=!(int)$x['claimed']&&time()>=(int)$x['started_at']+(int)$x['duration'];$workers[]=$x;} $x=$s->fetch();respond(200,['coins'=>(int)$x['coins'],'totalEarned'=>(int)$x['total_earned'],'workers'=>$workers]);
}
if ($action === 'farming-hire') {
    if (!moduleAllowed($db, 'farming')) respond(403, ['error' => 'Dieses Spiel wurde vom Administrator gesperrt.']);
 requireLogin();$uid=(int)$_SESSION['user_id'];$db->beginTransaction();$db->prepare('INSERT OR IGNORE INTO farming_state(user_id) VALUES(?)')->execute([$uid]);$s=$db->prepare('SELECT coins FROM farming_state WHERE user_id=?');$s->execute([$uid]);if((int)$s->fetchColumn()<50){$db->rollBack();respond(400,['error'=>'Du brauchst 50 Münzen.']);}$q=$db->prepare('SELECT COUNT(*) FROM farming_workers WHERE user_id=?');$q->execute([$uid]);if((int)$q->fetchColumn()>=50){$db->rollBack();respond(400,['error'=>'Maximal 50 Farmer.']);}$db->prepare('UPDATE farming_state SET coins=coins-50 WHERE user_id=?')->execute([$uid]);$db->prepare("INSERT INTO farming_workers(user_id,crop_key,started_at,duration,reward) VALUES(?,'wheat',?,30,5)")->execute([$uid,time()]);$db->commit();respond(200,['hired'=>true]);
}
if ($action === 'farming-plant') {
    if (!moduleAllowed($db, 'farming')) respond(403, ['error' => 'Dieses Spiel wurde vom Administrator gesperrt.']);
 requireLogin();$b=json_decode(file_get_contents('php://input')?:'',true);$c=['wheat'=>[30,5],'carrot'=>[60,12],'potato'=>[90,20],'corn'=>[180,45]];$id=(int)($b['workerId']??0);$key=(string)($b['crop']??'');if(!isset($c[$key]))respond(400,['error'=>'Ungültige Pflanze.']);$uid=(int)$_SESSION['user_id'];$q=$db->prepare('SELECT claimed FROM farming_workers WHERE id=? AND user_id=?');$q->execute([$id,$uid]);$x=$q->fetch();if(!$x||$x['claimed'])respond(404,['error'=>'Farmer nicht gefunden.']);$db->prepare('UPDATE farming_workers SET crop_key=?,started_at=?,duration=?,reward=? WHERE id=? AND user_id=?')->execute([$key,time(),$c[$key][0],$c[$key][1],$id,$uid]);respond(200,['planted'=>true]);
}
if ($action === 'farming-collect') {
    if (!moduleAllowed($db, 'farming')) respond(403, ['error' => 'Dieses Spiel wurde vom Administrator gesperrt.']);
 requireLogin();$b=json_decode(file_get_contents('php://input')?:'',true);$id=(int)($b['workerId']??0);$uid=(int)$_SESSION['user_id'];$db->beginTransaction();$q=$db->prepare('SELECT started_at,duration,reward,claimed FROM farming_workers WHERE id=? AND user_id=?');$q->execute([$id,$uid]);$x=$q->fetch();if(!$x||$x['claimed']||time()<(int)$x['started_at']+(int)$x['duration']){$db->rollBack();respond(400,['error'=>'Ernte noch nicht bereit.']);}$db->prepare('UPDATE farming_workers SET claimed=1 WHERE id=?')->execute([$id]);$db->prepare('UPDATE farming_state SET coins=coins+?,total_earned=total_earned+? WHERE user_id=?')->execute([(int)$x['reward'],(int)$x['reward'],$uid]);$db->commit();respond(200,['collected'=>true]);
}
if ($action === 'farming-leaderboard') {
    if (!moduleAllowed($db, 'farming')) respond(403, ['error' => 'Dieses Spiel wurde vom Administrator gesperrt.']);
 requireLogin();$rows=$db->query('SELECT u.id,u.username,u.created_at,u.is_admin,COALESCE(f.total_earned,0) score FROM users u LEFT JOIN farming_state f ON f.user_id=u.id ORDER BY score DESC,u.username COLLATE NOCASE LIMIT 10')->fetchAll();$out=[];foreach($rows as $i=>$r){$b=[];if((int)$r['is_admin']===1||strtolower($r['username'])==='antonfischle')$b[]=['icon'=>'🛡️','label'=>'Admin'];if(strtotime($r['created_at'])<=time()-31536000)$b[]=['icon'=>'🎂','label'=>'1 Jahr Mitglied'];if((int)$r['score']>0&&$i<10)$b[]=['icon'=>'🏆','label'=>'Farming Top 10'];if((int)$r['score']>0&&$i===0)$b[]=['icon'=>'👑','label'=>'Farming Top 1'];$q=$db->prepare('SELECT badge_key FROM user_badges WHERE user_id=?');$q->execute([(int)$r['id']]);foreach($q->fetchAll(PDO::FETCH_COLUMN) as $k){if($k==='supporter')$b[]=['icon'=>'💚','label'=>'Supporter'];if($k==='vip')$b[]=['icon'=>'💎','label'=>'VIP'];}$out[]=['username'=>$r['username'],'score'=>(int)$r['score'],'rank'=>$i+1,'badges'=>$b];}respond(200,['users'=>$out]);
}
if ($action === 'clicker-state') {
    if ($method !== 'GET') respond(405, ['error' => 'Diese Anfrage ist nicht erlaubt.']);
    requireLogin();
    $userId = (int)$_SESSION['user_id'];
    $db->prepare('INSERT OR IGNORE INTO clicker_scores (user_id) VALUES (?)')->execute([$userId]);
    $stmt = $db->prepare('SELECT score, power, upgrade_cost, auto_clicks, auto_cost, multiplier, multiplier_cost, super_bonus, super_cost FROM clicker_scores WHERE user_id = ?');
    $stmt->execute([$userId]); $s = $stmt->fetch();
    $rankStmt = $db->prepare('SELECT COUNT(*) + 1 FROM clicker_scores WHERE score > (SELECT score FROM clicker_scores WHERE user_id = ?)'); $rankStmt->execute([$userId]);
    respond(200, ['score'=>(int)$s['score'],'power'=>(int)$s['power'],'cost'=>(int)$s['upgrade_cost'],'auto'=>(int)$s['auto_clicks'],'autoCost'=>(int)$s['auto_cost'],'multiplier'=>(int)$s['multiplier'],'multiplierCost'=>(int)$s['multiplier_cost'],'super'=>(int)$s['super_bonus'],'superCost'=>(int)$s['super_cost'],'rank'=>(int)$rankStmt->fetchColumn()]);
}
if ($action === 'clicker-save') {
    if (!moduleAllowed($db, 'clicker')) respond(403, ['error' => 'Dieses Spiel wurde vom Administrator gesperrt.']);
    if ($method !== 'POST') { header('Allow: POST'); respond(405, ['error' => 'Diese Anfrage ist nicht erlaubt.']); }
    requireLogin();
    $body = json_decode(file_get_contents('php://input') ?: '', true);
    if (!is_array($body)) respond(400, ['error' => 'Ungültige Anfrage.']);
    foreach (['score','power','cost','auto','autoCost','multiplier','multiplierCost','super','superCost'] as $key) if (!isset($body[$key]) || !is_int($body[$key])) respond(400, ['error' => 'Ungültiger Spielstand.']);
    $score=$body['score']; $power=$body['power']; $cost=$body['cost']; $auto=$body['auto']; $autoCost=$body['autoCost']; $multiplier=$body['multiplier']; $multiplierCost=$body['multiplierCost']; $super=$body['super']; $superCost=$body['superCost'];
    if ($score<0 || $score>2000000000 || $power<1 || $power>1000000 || $cost<25 || $cost>2000000000 || $auto<0 || $auto>1000000 || $autoCost<100 || $autoCost>2000000000 || $multiplier<1 || $multiplier>1000000 || $multiplierCost<250 || $multiplierCost>2000000000 || $super<0 || $super>1000000 || $superCost<1000 || $superCost>2000000000) respond(400, ['error'=>'Spielstand außerhalb des erlaubten Bereichs.']);
    $db->prepare('INSERT INTO clicker_scores (user_id,score,power,upgrade_cost,auto_clicks,auto_cost,multiplier,multiplier_cost,super_bonus,super_cost,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)
        ON CONFLICT(user_id) DO UPDATE SET score=excluded.score,power=excluded.power,upgrade_cost=excluded.upgrade_cost,auto_clicks=excluded.auto_clicks,auto_cost=excluded.auto_cost,multiplier=excluded.multiplier,multiplier_cost=excluded.multiplier_cost,super_bonus=excluded.super_bonus,super_cost=excluded.super_cost,updated_at=CURRENT_TIMESTAMP')
        ->execute([(int)$_SESSION['user_id'],$score,$power,$cost,$auto,$autoCost,$multiplier,$multiplierCost,$super,$superCost]);
    respond(200, ['saved'=>true]);
}
if ($action === 'clicker-leaderboard') {
    if (!moduleAllowed($db, 'clicker')) respond(403, ['error' => 'Dieses Spiel wurde vom Administrator gesperrt.']);
    if ($method !== 'GET') respond(405, ['error'=>'Diese Anfrage ist nicht erlaubt.']); requireLogin();
    $rows=$db->query('SELECT u.id,u.username,u.created_at,u.is_admin,COALESCE(c.score,0) score FROM users u LEFT JOIN clicker_scores c ON c.user_id=u.id ORDER BY score DESC,u.username COLLATE NOCASE ASC LIMIT 10')->fetchAll();
    $users=[];
    foreach($rows as $i=>$row) {
        $uid=(int)$row['id']; $score=(int)$row['score']; $badges=[];
        if ((int)$row['is_admin']===1 || strtolower((string)$row['username'])==='antonfischle') $badges[]=['key'=>'admin','label'=>'Admin','icon'=>'🛡️'];
        if (strtotime((string)$row['created_at'])<=time()-31536000) $badges[]=['key'=>'year-member','label'=>'1 Jahr Mitglied','icon'=>'🎂'];
        if ($score>0 && $i<10) $badges[]=['key'=>'clicker-top-10','label'=>'Clicker Top 10','icon'=>'🏆'];
        if ($score>0 && $i===0) $badges[]=['key'=>'clicker-top-1','label'=>'Clicker Top 1','icon'=>'👑'];
        $bs=$db->prepare('SELECT badge_key FROM user_badges WHERE user_id=?'); $bs->execute([$uid]);
        foreach($bs->fetchAll(PDO::FETCH_COLUMN) as $key) { if($key==='supporter') $badges[]=['key'=>'supporter','label'=>'Supporter','icon'=>'💚']; if($key==='vip') $badges[]=['key'=>'vip','label'=>'VIP','icon'=>'💎']; }
        $users[]=['username'=>(string)$row['username'],'score'=>$score,'rank'=>$i+1,'badges'=>$badges];
    }
    respond(200,['users'=>$users]);
}

if ($action === 'profile-save') {
    if ($method !== 'POST') respond(405, ['error' => 'Diese Anfrage ist nicht erlaubt.']);
    requireLogin();
    $input = json_decode((string)file_get_contents('php://input'), true);
    if (!is_array($input)) respond(400, ['error' => 'Ungültige Daten.']);
    $bio = trim((string)($input['bio'] ?? ''));
    $avatar = trim((string)($input['avatar_url'] ?? ''));
    if (mb_strlen($bio) > 500) respond(400, ['error' => 'Die Bio darf höchstens 500 Zeichen lang sein.']);
    if ($avatar !== '' && (!filter_var($avatar, FILTER_VALIDATE_URL) || !in_array(strtolower((string)parse_url($avatar, PHP_URL_SCHEME)), ['https','http'], true))) respond(400, ['error' => 'Bitte gib eine gültige Bild-URL ein.']);
    if (strlen($avatar) > 1500) respond(400, ['error' => 'Die Bild-URL ist zu lang.']);
    $stmt = $db->prepare('INSERT INTO user_profiles(user_id,bio,avatar_url) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET bio=excluded.bio, avatar_url=excluded.avatar_url');
    $stmt->execute([(int)$_SESSION['user_id'], $bio, $avatar]);
    respond(200, ['saved' => true]);
}
if ($action === 'profile-get') {
    if ($method !== 'GET') respond(405, ['error' => 'Diese Anfrage ist nicht erlaubt.']);
    requireLogin();
    $requestedUsername = trim((string)($_GET['username'] ?? ''));
    $username = strtolower($requestedUsername !== '' ? $requestedUsername : (string)($_SESSION['username'] ?? ''));
    $stmt = $db->prepare('SELECT id,username,created_at,is_admin FROM users WHERE username_key=?');
    $stmt->execute([$username]); $u = $stmt->fetch();
    if (!$u) respond(404, ['error' => 'Benutzer nicht gefunden.']);
    $uid = (int)$u['id'];
    $p = $db->prepare('SELECT bio,avatar_url FROM user_profiles WHERE user_id=?'); $p->execute([$uid]);
    $profile = $p->fetch() ?: ['bio'=>'','avatar_url'=>''];
    $sc = $db->prepare('SELECT score FROM clicker_scores WHERE user_id=?'); $sc->execute([$uid]); $score=(int)($sc->fetchColumn() ?: 0);
    $rk = $db->prepare('SELECT COUNT(*)+1 FROM clicker_scores WHERE score>?'); $rk->execute([$score]); $rank=(int)$rk->fetchColumn();
    $badges=[];
    if ((int)$u['is_admin']===1 || $username==='antonfischle') $badges[]=['label'=>'Admin','icon'=>'🛡️'];
    if (strtotime((string)$u['created_at'])<=time()-31536000) $badges[]=['label'=>'1 Jahr Mitglied','icon'=>'🎂'];
    if ($score>0 && $rank<=10) $badges[]=['label'=>'Clicker Top 10','icon'=>'🏆'];
    if ($score>0 && $rank===1) $badges[]=['label'=>'Clicker Top 1','icon'=>'👑'];
    $bs=$db->prepare('SELECT badge_key FROM user_badges WHERE user_id=?'); $bs->execute([$uid]);
    foreach ($bs->fetchAll(PDO::FETCH_COLUMN) as $key) { if($key==='supporter') $badges[]=['label'=>'Supporter','icon'=>'💚']; if($key==='vip') $badges[]=['label'=>'VIP','icon'=>'💎']; }
    respond(200, ['username'=>(string)$u['username'], 'bio'=>(string)$profile['bio'], 'avatar_url'=>(string)$profile['avatar_url'], 'badges'=>$badges, 'score'=>$score, 'rank'=>$rank, 'isOwn'=>((int)$u['id']===(int)$_SESSION['user_id'])]);
}

if ($action === 'user-profile') {
    if ($method !== 'GET') respond(405,['error'=>'Diese Anfrage ist nicht erlaubt.']); requireLogin();
    $username=strtolower(trim((string)($_GET['username']??''))); $stmt=$db->prepare('SELECT id,username,created_at,is_admin FROM users WHERE username_key=?'); $stmt->execute([$username]); $u=$stmt->fetch();
    if(!$u) respond(404,['error'=>'Benutzer nicht gefunden.']);
    $uid=(int)$u['id']; $ss=$db->prepare('SELECT score FROM clicker_scores WHERE user_id=?'); $ss->execute([$uid]); $score=(int)($ss->fetchColumn()?:0);
    $rankStmt=$db->prepare('SELECT COUNT(*)+1 FROM clicker_scores WHERE score>?'); $rankStmt->execute([$score]); $rank=(int)$rankStmt->fetchColumn(); $badges=[];
    if((int)$u['is_admin']===1 || $username==='antonfischle') $badges[]=['key'=>'admin','label'=>'Admin','icon'=>'🛡️'];
    if(strtotime((string)$u['created_at'])<=time()-31536000) $badges[]=['key'=>'year-member','label'=>'1 Jahr Mitglied','icon'=>'🎂'];
    if($score>0 && $rank<=10) $badges[]=['key'=>'clicker-top-10','label'=>'Clicker Top 10','icon'=>'🏆'];
    if($score>0 && $rank===1) $badges[]=['key'=>'clicker-top-1','label'=>'Clicker Top 1','icon'=>'👑'];
    $bs=$db->prepare('SELECT badge_key FROM user_badges WHERE user_id=?'); $bs->execute([$uid]);
    foreach($bs->fetchAll(PDO::FETCH_COLUMN) as $key) { if($key==='supporter') $badges[]=['key'=>'supporter','label'=>'Supporter','icon'=>'💚']; if($key==='vip') $badges[]=['key'=>'vip','label'=>'VIP','icon'=>'💎']; }
    respond(200,['username'=>(string)$u['username'],'score'=>$score,'rank'=>$rank,'badges'=>$badges]);
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
    if (!in_array($module, ['activity', 'clicker', 'farming'], true)) respond(400, ['error' => 'Dieses Modul kann nicht verwaltet werden.']);
    if (!in_array($scope, ['all', 'user'], true)) respond(400, ['error' => 'Ungültiger Geltungsbereich.']);
    if ($scope === 'user' && !preg_match('/^[a-zA-Z0-9_-]{3,32}$/', $username)) respond(400, ['error' => 'Bitte wähle einen gültigen Benutzer.']);
    try {
        if ($scope === 'all') {
            // Eine globale Änderung muss wirklich für alle Konten gelten.
            // Alte benutzerspezifische Ausnahmen für dieses Modul entfernen,
            // damit ein zuvor erlaubter Einzelzugriff die globale Sperre nicht aushebelt.
            $db->prepare('DELETE FROM module_permissions WHERE module = ?')->execute([$module]);
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


function requireFilesAdmin(): void {
    requireAdmin();
}

function filesStorageDir(): string {
    $dir = __DIR__ . DIRECTORY_SEPARATOR . 'private-files' . DIRECTORY_SEPARATOR . 'uploads';
    if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
        respond(500, ['error' => 'Der Upload-Ordner konnte nicht erstellt werden.']);
    }
    // Apache: uploaded content must never be reachable directly.
    $htaccess = __DIR__ . DIRECTORY_SEPARATOR . 'private-files' . DIRECTORY_SEPARATOR . '.htaccess';
    if (!is_file($htaccess)) {
        @file_put_contents($htaccess, "Require all denied\\nDeny from all\\n");
    }
    return $dir;
}

function safeStoredFile(string $id): ?string {
    if (!preg_match('/^[a-f0-9]{32}$/', $id)) return null;
    $path = filesStorageDir() . DIRECTORY_SEPARATOR . $id . '.bin';
    return is_file($path) && is_readable($path) ? $path : null;
}

if (in_array($action, ['files', 'file-upload', 'file-view', 'file-delete'], true)) {
    requireFilesAdmin();

    if ($action === 'files') {
        if ($method !== 'GET') respond(405, ['error' => 'Diese Anfrage ist nicht erlaubt.']);
        $dir = filesStorageDir();
        $items = [];
        foreach (glob($dir . DIRECTORY_SEPARATOR . '*.json') ?: [] as $metaPath) {
            $meta = json_decode((string)file_get_contents($metaPath), true);
            if (!is_array($meta) || !preg_match('/^[a-f0-9]{32}$/', (string)($meta['id'] ?? ''))) continue;
            $stored = safeStoredFile((string)$meta['id']);
            if (!$stored) continue;
            $items[] = [
                'id' => $meta['id'],
                'name' => (string)($meta['name'] ?? 'Datei'),
                'size' => filesize($stored) ?: 0,
                'type' => (string)($meta['type'] ?? 'application/octet-stream'),
                'uploadedAt' => (string)($meta['uploadedAt'] ?? '')
            ];
        }
        usort($items, static fn(array $a, array $b): int => strcmp($b['uploadedAt'], $a['uploadedAt']));
        respond(200, ['files' => $items]);
    }

    if ($action === 'file-upload') {
        if ($method !== 'POST') respond(405, ['error' => 'Diese Anfrage ist nicht erlaubt.']);
        if (!isset($_FILES['upload']) || !is_array($_FILES['upload'])) respond(400, ['error' => 'Bitte wähle eine Datei aus.']);
        $upload = $_FILES['upload'];
        if (($upload['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) respond(400, ['error' => 'Upload fehlgeschlagen. Die Datei ist eventuell zu groß.']);
        if (!is_uploaded_file((string)$upload['tmp_name'])) respond(400, ['error' => 'Ungültiger Upload.']);
        if ((int)$upload['size'] < 1 || (int)$upload['size'] > 10 * 1024 * 1024) respond(413, ['error' => 'Dateien dürfen maximal 10 MB groß sein.']);
        $originalName = basename(str_replace('\\\\', '/', (string)$upload['name']));
        $originalName = preg_replace('/[\\x00-\\x1F\\x7F]/u', '', $originalName) ?: 'Datei';
        $originalName = mb_substr($originalName, 0, 180, 'UTF-8');
        $mime = 'application/octet-stream';
        if (class_exists('finfo')) {
            $finfo = new finfo(FILEINFO_MIME_TYPE);
            $detected = $finfo->file((string)$upload['tmp_name']);
            if (is_string($detected) && $detected !== '') $mime = $detected;
        }
        $id = bin2hex(random_bytes(16));
        $dir = filesStorageDir();
        if (!move_uploaded_file((string)$upload['tmp_name'], $dir . DIRECTORY_SEPARATOR . $id . '.bin')) respond(500, ['error' => 'Datei konnte nicht gespeichert werden.']);
        $meta = ['id' => $id, 'name' => $originalName, 'type' => $mime, 'uploadedAt' => gmdate('c')];
        if (file_put_contents($dir . DIRECTORY_SEPARATOR . $id . '.json', json_encode($meta, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), LOCK_EX) === false) {
            @unlink($dir . DIRECTORY_SEPARATOR . $id . '.bin');
            respond(500, ['error' => 'Dateiinformationen konnten nicht gespeichert werden.']);
        }
        respond(201, ['ok' => true, 'file' => ['id' => $id, 'name' => $originalName, 'type' => $mime, 'size' => (int)$upload['size'], 'uploadedAt' => $meta['uploadedAt']]]);
    }

    $id = (string)($_GET['id'] ?? '');
    $stored = safeStoredFile($id);
    $metaPath = filesStorageDir() . DIRECTORY_SEPARATOR . $id . '.json';
    $meta = is_file($metaPath) ? json_decode((string)file_get_contents($metaPath), true) : null;
    if (!$stored || !is_array($meta)) respond(404, ['error' => 'Datei nicht gefunden.']);

    if ($action === 'file-delete') {
        if ($method !== 'POST') respond(405, ['error' => 'Diese Anfrage ist nicht erlaubt.']);
        @unlink($stored);
        @unlink($metaPath);
        respond(200, ['ok' => true]);
    }

    if ($method !== 'GET') respond(405, ['error' => 'Diese Anfrage ist nicht erlaubt.']);
    $mime = (string)($meta['type'] ?? 'application/octet-stream');
    $name = (string)($meta['name'] ?? 'Datei');
    $previewable = str_starts_with($mime, 'image/') || str_starts_with($mime, 'text/') || in_array($mime, ['application/pdf', 'application/json', 'application/xml', 'application/javascript'], true);
    $safeInlineTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/avif', 'image/svg+xml', 'application/pdf'];
    if (str_starts_with($mime, 'text/') || in_array($mime, ['application/json', 'application/xml', 'application/javascript'], true)) $mime = 'text/plain';
    if (!in_array($mime, $safeInlineTypes, true) && !str_starts_with($mime, 'text/')) $previewable = false;
    header('Content-Type: ' . ($previewable ? $mime : 'application/octet-stream') . (str_starts_with($mime, 'text/') ? '; charset=utf-8' : ''));
    header('Content-Length: ' . (string)filesize($stored));
    header('Content-Disposition: ' . ($previewable ? 'inline' : 'attachment') . '; filename="' . str_replace(['"', "\\\\", "\\r", "\\n"], ['_', '_', '', ''], $name) . '"');
    header('X-Content-Type-Options: nosniff');
    readfile($stored);
    exit;
}

if ($action === 'module-access') {
    if ($method !== 'GET') respond(405, ['error' => 'Diese Anfrage ist nicht erlaubt.']);
    requireLogin();
    $usernameKey = strtolower((string)($_SESSION['username'] ?? ''));
    if (isAdmin()) respond(200, ['access' => ['files' => true, 'activity' => true, 'clicker' => true, 'farming' => true]]);
    $stmt = $db->prepare("SELECT module, allowed FROM module_permissions WHERE username_key IN ('*', ?) ORDER BY username_key");
    $stmt->execute([$usernameKey]);
    $access = ['files' => false, 'activity' => true, 'clicker' => true, 'farming' => true];
    foreach ($stmt->fetchAll() as $row) {
        $access[(string)$row['module']] = (int)$row['allowed'] === 1;
    }
    respond(200, ['access' => $access]);
}

function moduleAllowed(PDO $db, string $module): bool {
    if ($module === 'files') return isAdmin();
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
