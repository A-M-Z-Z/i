<?php
session_start(); // Start session

// Check if user is logged in and is an admin
if (!isset($_SESSION['username']) || !isset($_SESSION['user_id']) || !isset($_SESSION['is_admin']) || $_SESSION['is_admin'] != 1) {
    header("Location: expired");  // Redirect to expired page if not admin
    exit();
}

// Database Connection
$host = 'localhost';
$user = 'root';
$pass = 'root';
$dbname = 'cloudbox';
$conn = new mysqli($host, $user, $pass, $dbname);
if ($conn->connect_error) die("Database connection failed: " . $conn->connect_error);
$conn->options(MYSQLI_OPT_CONNECT_TIMEOUT, 60);

$username = $_SESSION['username'];
$userid = $_SESSION['user_id'];

// Handle user deletion
if (isset($_GET['delete_user']) && is_numeric($_GET['delete_user'])) {
    $user_id = intval($_GET['delete_user']);
    // Don't allow admin to delete themselves
    if ($user_id != $userid) {
        $deleteStmt = $conn->prepare("DELETE FROM users WHERE id = ?");
        $deleteStmt->bind_param("i", $user_id);
        if ($deleteStmt->execute()) {
            $message = "<div class='alert alert-success'>User deleted successfully.</div>";
        } else {
            $message = "<div class='alert alert-danger'>Error deleting user.</div>";
        }
    } else {
        $message = "<div class='alert alert-danger'>You cannot delete yourself!</div>";
    }
}

// Handle admin promotion/demotion
if (isset($_GET['toggle_admin']) && is_numeric($_GET['toggle_admin'])) {
    $user_id = intval($_GET['toggle_admin']);
    // Don't allow admin to demote themselves
    if ($user_id != $userid) {
        // First check current admin status
        $checkStmt = $conn->prepare("SELECT is_admin FROM users WHERE id = ?");
        $checkStmt->bind_param("i", $user_id);
        $checkStmt->execute();
        $checkStmt->bind_result($is_admin);
        $checkStmt->fetch();
        $checkStmt->close();
        
        // Toggle admin status
        $new_status = $is_admin ? 0 : 1;
        $updateStmt = $conn->prepare("UPDATE users SET is_admin = ? WHERE id = ?");
        $updateStmt->bind_param("ii", $new_status, $user_id);
        if ($updateStmt->execute()) {
            $message = "<div class='alert alert-success'>User admin status updated successfully.</div>";
        } else {
            $message = "<div class='alert alert-danger'>Error updating user admin status.</div>";
        }
    } else {
        $message = "<div class='alert alert-danger'>You cannot change your own admin status!</div>";
    }
}

// Handle storage quota update
if (isset($_GET['update_quota']) && is_numeric($_GET['update_quota']) && isset($_POST['quota'])) {
    $user_id = intval($_GET['update_quota']);
    $quota_mb = intval($_POST['quota']);
    
    // Convert MB to bytes (minimum 1MB)
    $quota_bytes = max(1048576, $quota_mb * 1048576);
    
    $updateStmt = $conn->prepare("UPDATE users SET storage_quota = ? WHERE id = ?");
    $updateStmt->bind_param("ii", $quota_bytes, $user_id);
    if ($updateStmt->execute()) {
        $message = "<div class='alert alert-success'>User storage quota updated successfully.</div>";
    } else {
        $message = "<div class='alert alert-danger'>Error updating user storage quota.</div>";
    }
}

// Handle viewing user files
$view_user_id = isset($_GET['view_files']) && is_numeric($_GET['view_files']) ? intval($_GET['view_files']) : null;

// Fetch system statistics
$userCount = $conn->query("SELECT COUNT(*) FROM users")->fetch_row()[0];
$fileCount = $conn->query("SELECT COUNT(*) FROM files")->fetch_row()[0];
$totalStorage = $conn->query("SELECT SUM(file_size) FROM files")->fetch_row()[0];
$adminCount = $conn->query("SELECT COUNT(*) FROM users WHERE is_admin = 1")->fetch_row()[0];

// Fetch users for the management table
$result = $conn->query("SELECT u.id, u.username, u.email, u.full_name, u.is_admin, 
                        u.storage_quota,
                        (SELECT SUM(file_size) FROM files WHERE user_id = u.id) as storage 
                        FROM users u ORDER BY u.id");
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CloudBOX - Admin Dashboard</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <!-- Font Awesome for icons -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body>
     <div class="top-bar">
        <div class="logo">
            <img src="logo.png" alt="CloudBOX Logo" height="40">
        </div>
        <h1>CloudBOX</h1>
        <div class="search-bar">
            <input type="text" placeholder="Search files and folders..." class="form-control">
        </div>
    </div>
    
    <nav class="dashboard-nav">
        <a href="home"><i class="fas fa-tachometer-alt"></i> Dashboard</a>
        <a href="drive"><i class="fas fa-folder"></i> My Drive</a>
        <?php if(isset($_SESSION['is_admin']) && $_SESSION['is_admin'] == 1): ?>
        <a href="admin"><i class="fas fa-crown"></i> Admin Panel</a>
        <?php endif; ?>
        <a href="shared"><i class="fas fa-share-alt"></i> Shared Files</a>
        <a href="monitoring"><i class="fas fa-chart-line"></i> Monitoring</a>
        <a href="logout"><i class="fas fa-sign-out-alt"></i> Logout</a>
    </nav>

    <!-- Main Content -->
    <div class="container-fluid mt-4">
        <?php 
        // Display any system messages
        if (isset($message)) {
            echo $message;
        }
        ?>

        <div class="row">
            <!-- System Statistics -->
            <div class="col-12">
                <div class="row g-3">
                    <div class="col-md-3">
                        <div class="card text-center">
                            <div class="card-body">
                                <h5 class="card-title">Total Users</h5>
                                <p class="display-6 fw-bold text-primary"><?= $userCount ?></p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card text-center">
                            <div class="card-body">
                                <h5 class="card-title">Total Files</h5>
                                <p class="display-6 fw-bold text-success"><?= $fileCount ?></p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card text-center">
                            <div class="card-body">
                                <h5 class="card-title">Storage Used</h5>
                                <p class="display-6 fw-bold text-warning"><?= number_format($totalStorage / (1024 * 1024), 2) ?> MB</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card text-center">
                            <div class="card-body">
                                <h5 class="card-title">Admins</h5>
                                <p class="display-6 fw-bold text-danger"><?= $adminCount ?></p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- User Management -->
            <div class="col-12 mt-4">
                <div class="card">
                    <div class="card-header bg-primary text-white">
                        <h3 class="card-title mb-0">User Management</h3>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-striped table-hover">
                                <thead class="table-light">
                                    <tr>
                                        <th>ID</th>
                                        <th>Username</th>
                                        <th>Email</th>
                                        <th>Storage Used</th>
                                        <th>Storage Quota</th>
                                        <th>Admin Status</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php while ($user = $result->fetch_assoc()): 
                                        // Calculate storage usage
                                        $storageInMB = number_format(($user['storage'] ?? 0) / (1024 * 1024), 2);
                                        $quotaInMB = number_format(($user['storage_quota'] ?? 104857600) / (1024 * 1024), 0);
                                        $usagePercent = ($user['storage'] && $user['storage_quota']) 
                                            ? min(100, round(($user['storage'] / $user['storage_quota']) * 100)) 
                                            : 0;
                                    ?>
                                    <tr>
                                        <td><?= $user['id'] ?></td>
                                        <td><?= htmlspecialchars($user['username']) ?></td>
                                        <td><?= htmlspecialchars($user['email']) ?></td>
                                        <td>
                                            <div class="progress" style="height: 20px;">
                                                <div class="progress-bar" role="progressbar" 
                                                     style="width: <?= $usagePercent ?>%; 
                                                            background-color: <?= $usagePercent > 90 ? '#dc3545' : ($usagePercent > 70 ? '#ffc107' : '#28a745') ?>"
                                                     aria-valuenow="<?= $usagePercent ?>" 
                                                     aria-valuemin="0" 
                                                     aria-valuemax="100">
                                                    <?= $storageInMB ?> MB
                                                </div>
                                            </div>
                                        </td>
                                        <td>
                                            <form method="post" action="?update_quota=<?= $user['id'] ?>" class="input-group">
                                                <input type="number" name="quota" class="form-control" value="<?= $quotaInMB ?>" min="1">
                                                <button class="btn btn-primary" type="submit">Update</button>
                                            </form>
                                        </td>
                                        <td>
                                            <span class="badge <?= $user['is_admin'] == 1 ? 'bg-success' : 'bg-secondary' ?>">
                                                <?= $user['is_admin'] == 1 ? 'Admin' : 'User' ?>
                                            </span>
                                        </td>
                                        <td>
                                            <div class="btn-group" role="group">
                                                <a href="?view_files=<?= $user['id'] ?>" class="btn btn-sm btn-info">
                                                    <i class="fas fa-eye"></i>
                                                </a>
                                                <a href="?toggle_admin=<?= $user['id'] ?>" class="btn btn-sm btn-warning">
                                                    <i class="fas fa-user-cog"></i>
                                                </a>
                                                <a href="?delete_user=<?= $user['id'] ?>" class="btn btn-sm btn-danger" onclick="return confirm('Are you sure?')">
                                                    <i class="fas fa-trash"></i>
                                                </a>
                                            </div>
                                        </td>
                                    </tr>
                                    <?php endwhile; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Recent System Activity -->
            <div class="col-12 mt-4">
                <div class="card">
                    <div class="card-header bg-primary text-white">
                        <h3 class="card-title mb-0">Recent System Activity</h3>
                    </div>
                    <div class="card-body">
                        <p class="text-muted">This section could display login attempts, file uploads, deletions, etc.</p>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Bootstrap Bundle with Popper -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
    
    <script>
        // Simple script to hide messages
        setTimeout(function() {
            var messageElements = document.querySelectorAll('.alert');
            messageElements.forEach(function(el) {
                el.style.display = 'none';
            });
        }, 3000);
    </script>
</body>
</html>
