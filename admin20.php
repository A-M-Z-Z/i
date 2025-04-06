<?php
session_start(); // Start session

// Check if user is logged in and is an admin
if (!isset($_SESSION['username']) || !isset($_SESSION['user_id']) || !isset($_SESSION['is_admin']) || $_SESSION['is_admin'] != 1) {
    header("Location: expired.php");  // Redirect to expired page if not admin
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

// Initialize messages array
$messages = [];

// Handle user deletion
if (isset($_GET['delete_user']) && is_numeric($_GET['delete_user'])) {
    $user_id = intval($_GET['delete_user']);
    // Don't allow admin to delete themselves
    if ($user_id != $userid) {
        $deleteStmt = $conn->prepare("DELETE FROM users WHERE id = ?");
        $deleteStmt->bind_param("i", $user_id);
        if ($deleteStmt->execute()) {
            $messages[] = "<div class='alert alert-success'>User deleted successfully.</div>";
        } else {
            $messages[] = "<div class='alert alert-danger'>Error deleting user.</div>";
        }
    } else {
        $messages[] = "<div class='alert alert-danger'>You cannot delete yourself!</div>";
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
            $messages[] = "<div class='alert alert-success'>User admin status updated successfully.</div>";
        } else {
            $messages[] = "<div class='alert alert-danger'>Error updating user admin status.</div>";
        }
    } else {
        $messages[] = "<div class='alert alert-danger'>You cannot change your own admin status!</div>";
    }
}

// Handle storage quota update
if (isset($_POST['update_quota']) && isset($_POST['user_id']) && isset($_POST['quota_mb'])) {
    $user_id = intval($_POST['user_id']);
    $quota_mb = intval($_POST['quota_mb']);
    
    // Validate the quota (minimum 10MB, maximum 10GB)
    $quota_mb = max(10, min(10240, $quota_mb));
    
    // Convert MB to bytes
    $quota_bytes = $quota_mb * 1024 * 1024;
    
    $updateStmt = $conn->prepare("UPDATE users SET storage_quota = ? WHERE id = ?");
    $updateStmt->bind_param("ii", $quota_bytes, $user_id);
    if ($updateStmt->execute()) {
        $messages[] = "<div class='alert alert-success'>Storage quota updated successfully.</div>";
    } else {
        $messages[] = "<div class='alert alert-danger'>Error updating storage quota.</div>";
    }
}

// Handle file deletion
if (isset($_GET['delete_file']) && is_numeric($_GET['delete_file']) && isset($_GET['view_files']) && is_numeric($_GET['view_files'])) {
    $file_id = intval($_GET['delete_file']);
    $view_user_id = intval($_GET['view_files']);
    
    $deleteFileStmt = $conn->prepare("DELETE FROM files WHERE id = ?");
    $deleteFileStmt->bind_param("i", $file_id);
    if ($deleteFileStmt->execute()) {
        $messages[] = "<div class='alert alert-success'>File deleted successfully.</div>";
    } else {
        $messages[] = "<div class='alert alert-danger'>Error deleting file.</div>";
    }
}

// Handle viewing user files
$view_user_id = isset($_GET['view_files']) && is_numeric($_GET['view_files']) ? intval($_GET['view_files']) : null;

// Fetch system statistics
$userCount = $conn->query("SELECT COUNT(*) FROM users")->fetch_row()[0];
$fileCount = $conn->query("SELECT COUNT(*) FROM files")->fetch_row()[0];
$totalStorage = $conn->query("SELECT SUM(file_size) FROM files")->fetch_row()[0] ?: 0;
$adminCount = $conn->query("SELECT COUNT(*) FROM users WHERE is_admin = 1")->fetch_row()[0];

// Format helper function
function format_file_size($bytes) {
    if ($bytes >= 1073741824) {
        return number_format($bytes / 1073741824, 2) . ' GB';
    } elseif ($bytes >= 1048576) {
        return number_format($bytes / 1048576, 2) . ' MB';
    } elseif ($bytes >= 1024) {
        return number_format($bytes / 1024, 2) . ' KB';
    } else {
        return $bytes . ' bytes';
    }
}
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
    <!-- Custom CSS -->
    <style>
        body {
            background-color: #f8f9fa;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .top-bar {
            background-color: #4f46e5;
            padding: 15px;
            display: flex;
            align-items: center;
            color: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .logo {
            margin-right: 15px;
        }
        
        .top-bar h1 {
            margin: 0;
            font-size: 22px;
        }
        
        .search-bar {
            margin-left: auto;
        }
        
        .search-bar input {
            border-radius: 20px;
            padding: 8px 15px;
            border: none;
            width: 250px;
        }
        
        .dashboard-nav {
            background-color: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 15px;
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            justify-content:center;
        }
        
        .dashboard-nav a {
            color: #4b5563;
            text-decoration: none;
            padding: 8px 15px;
            border-radius: 6px;
            transition: background-color 0.2s;
        }
        
        .dashboard-nav a:hover {
            background-color: #f3f4f6;
            color: #4f46e5;
        }
        
        main {
            max-width: 1200px;
            margin: 30px auto;
            padding: 0 20px;
        }
        
        .stats-container {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            margin-bottom: 20px;
        }
        
        .stat-card {
            background-color: #ffffff;
            border-left: 5px solid #4f46e5;
            border-radius: 8px;
            padding: 15px;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            flex: 1;
            min-width: 200px;
        }
        
        .stat-title {
            color: #6b7280;
            font-size: 14px;
            margin-bottom: 8px;
        }
        
        .stat-value {
            color: #1f2937;
            font-size: 24px;
            font-weight: bold;
        }
        
        .card {
            border: none;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            margin-bottom: 20px;
        }
        
        .card-header {
            background-color: white;
            border-bottom: 1px solid #e5e7eb;
            padding: 15px 20px;
            font-weight: 600;
        }
        
        .table th {
            font-weight: 600;
            color: #4b5563;
        }
        
        .progress {
            height: 8px;
            border-radius: 4px;
            background-color: #e5e7eb;
        }
        
        .btn-primary {
            background-color: #4f46e5;
            border-color: #4f46e5;
        }
        
        .btn-primary:hover {
            background-color: #4338ca;
            border-color: #4338ca;
        }

        /* Responsive tweaks */
        @media (max-width: 768px) {
            .stats-container {
                flex-direction: column;
            }
            
            .stat-card {
                min-width: 100%;
            }
            
            .search-bar input {
                width: 150px;
            }
        }
        /* Boutons plus petits pour la section Admin */
.btn-group-sm > .btn, .btn-sm {
    padding: 0.25rem 0.5rem;
    font-size: 0.75rem;
    line-height: 1.5;
    border-radius: 0.2rem;
}

/* Retirer l'espace pour les boutons avec icônes seulement */
.btn-sm i {
    margin-right: 0;
}

/* Optionnel - Réduire la largeur des boutons actions */
td .btn-group {
    white-space: nowrap;
}

/* Optionnel - Si vous voulez vraiment des boutons minimaux avec icônes uniquement */
td .btn-group .btn {
    padding-left: 0.4rem;
    padding-right: 0.4rem;
}
    </style>
</head>
<body>
    <div class="top-bar">
        <div class="logo">
            <img src="logo.png" alt="CloudBOX Logo" height="40">
        </div>
        <div class="search-bar">
            <input type="text" placeholder="Search files and folders..." class="form-control">
        </div>
    </div>
    
    <nav class="dashboard-nav">
        <a href="home.php"><i class="fas fa-tachometer-alt"></i> Dashboard</a>
        <?php if(isset($_SESSION['is_admin']) && $_SESSION['is_admin'] == 1): ?>
        <a href="admin.php"><i class="fas fa-crown"></i> Admin Panel</a>
        <?php endif; ?>
        <a href="shared.php"><i class="fas fa-share-alt"></i> Shared Files</a>
        <a href="monitoring.php"><i class="fas fa-chart-line"></i> Monitoring</a>
        <a href="logout.php"><i class="fas fa-sign-out-alt"></i> Logout</a>
    </nav>

    <main>
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h1 class="h3">Admin Dashboard</h1>
            <div>
                <span class="text-muted">Welcome, Admin <?= htmlspecialchars($username) ?>!</span>
            </div>
        </div>
        
        <!-- Display messages -->
        <?php foreach ($messages as $message): ?>
            <?= $message ?>
        <?php endforeach; ?>
        


        <?php else: ?>
            <!-- System Stats Section -->
            <div class="stats-container">
                <div class="stat-card">
                    <div class="stat-title">TOTAL USERS</div>
                    <div class="stat-value"><?= $userCount ?></div>
                </div>
                <div class="stat-card">
                    <div class="stat-title">TOTAL FILES</div>
                    <div class="stat-value"><?= $fileCount ?></div>
                </div>
                <div class="stat-card">
                    <div class="stat-title">STORAGE USED</div>
                    <div class="stat-value"><?= number_format($totalStorage / (1024 * 1024), 2) ?> MB</div>
                </div>
                <div class="stat-card">
                    <div class="stat-title">ADMINS</div>
                    <div class="stat-value"><?= $adminCount ?></div>
                </div>
            </div>
            
            <!-- User Management Section -->
            <div class="card">
                <div class="card-header">
                    <h5 class="mb-0"><i class="fas fa-users me-2"></i>User Management</h5>
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Username</th>
                                    <th>Email</th>
                                    <th>Full Name</th>
                                    <th>Storage Used</th>
                                    <th>Storage Quota</th>
                                    <th>Admin Status</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php
                                $result = $conn->query("SELECT u.id, u.username, u.email, u.full_name, u.is_admin, u.storage_quota, 
                                                      (SELECT SUM(file_size) FROM files WHERE user_id = u.id) as storage 
                                                      FROM users u ORDER BY u.id");
                                
                                while ($user = $result->fetch_assoc()) {
                                    $storageInMB = number_format(($user['storage'] ?? 0) / (1024 * 1024), 2);
                                    $quotaInMB = number_format(($user['storage_quota'] ?? 104857600) / (1024 * 1024), 0);
                                    
                                    // Calculate usage percentage for progress bar
                                    $usagePercent = ($user['storage'] && $user['storage_quota']) 
                                        ? min(100, round(($user['storage'] / $user['storage_quota']) * 100)) 
                                        : 0;
                                    
                                    $barColor = $usagePercent > 90 ? '#ef4444' : ($usagePercent > 70 ? '#f59e0b' : '#22c55e');
                                    
                                    echo "<tr>";
                                    echo "<td>" . $user['id'] . "</td>";
                                    echo "<td>" . htmlspecialchars($user['username']) . "</td>";
                                    echo "<td>" . htmlspecialchars($user['email']) . "</td>";
                                    echo "<td>" . htmlspecialchars($user['full_name']) . "</td>";
                                    echo "<td>
                                          <div class='progress mb-2'>
                                            <div class='progress-bar' role='progressbar' style='width: {$usagePercent}%; background-color: {$barColor};'></div>
                                          </div>
                                          {$storageInMB} MB ({$usagePercent}%)
                                        </td>";
                                    echo "<td>
                                          <form method='post' class='d-flex'>
                                            <input type='hidden' name='user_id' value='{$user['id']}'>
                                            <div class='input-group input-group-sm'>
                                              <input type='number' name='quota_mb' value='{$quotaInMB}' min='10' max='10240' class='form-control'>
                                              <button type='submit' name='update_quota' class='btn btn-primary'>Confirm</button>
                                            </div>
                                          </form>
                                        </td>";
                                    echo "<td><span class='badge " . ($user['is_admin'] == 1 ? "bg-primary" : "bg-secondary") . "'>" . 
                                          ($user['is_admin'] == 1 ? 'Admin' : 'User') . "</span></td>";
                                    echo "<td>
                                        <div class='btn-group btn-group-sm'>
                                            <a href='?view_files={$user['id']}' class='btn btn-primary'>
                                                <i class='fas fa-folder-open me-1'></i> View Files
                                            </a>
                                            <a href='?toggle_admin={$user['id']}' class='btn btn-secondary'>
                                                <i class='fas " . ($user['is_admin'] == 1 ? "fa-user" : "fa-crown") . " me-1'></i> " . 
                                                ($user['is_admin'] == 1 ? 'Remove Admin' : 'Make Admin') . "
                                            </a>
                                            <a href='?delete_user={$user['id']}' class='btn btn-danger' 
                                               onclick='return confirm(\"Are you sure you want to delete this user? All their files will be deleted as well.\");'>
                                                <i class='fas fa-trash me-1'></i> Delete
                                            </a>
                                        </div>
                                    </td>";
                                    echo "</tr>";
                                }
                                ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            
            <!-- System Logs Section -->
            <div class="card">
                <div class="card-header">
                    <h5 class="mb-0"><i class="fas fa-history me-2"></i>Recent System Activity</h5>
                </div>
                <div class="card-body">
                    <p class="text-muted">This section displays recent login attempts, file uploads, and other system activities.</p>
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead>
                                <tr>
                                    <th>Time</th>
                                    <th>User</th>
                                    <th>Action</th>
                                    <th>Details</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td colspan="4" class="text-center">Logging system not implemented yet. This feature will be available soon.</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        <?php endif; ?>
    </main>

    <!-- Bootstrap Bundle with Popper -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
    
    <script>
        // Auto-hide alerts after 3 seconds
        setTimeout(function() {
            const alerts = document.querySelectorAll('.alert');
            alerts.forEach(alert => {
                // Create a Bootstrap alert instance
                const bsAlert = new bootstrap.Alert(alert);
                // Use Bootstrap's hide method
                bsAlert.close();
            });
        }, 3000);
    </script>
</body>
</html>
