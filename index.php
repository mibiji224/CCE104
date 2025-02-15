<?php
session_start();
$conn = new mysqli('localhost', 'root', '', 'your_database');

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = htmlspecialchars($_POST['username']);
    $password = $_POST['password'];

    $sql = "SELECT * FROM users WHERE username=?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        if (password_verify($password, $row['password'])) {
            $_SESSION['user_id'] = $row['id'];
            $_SESSION['username'] = $row['username'];
            $_SESSION['role'] = $row['role'];

            $stmt->close();
            $conn->close();

            if ($row['role'] == 'admin') {
                header("Location: dashboard.php");
            } else {
                header("Location: landing.php");
            }
            exit();
        }
    }

    $_SESSION['error'] = "Invalid username or password.";
    $stmt->close();
    $conn->close();
    header("Location: index.php");
    exit();
}
?>
