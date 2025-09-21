<?php
$valid_users = [
  "<USERNAME>" => "<PASSWORD>",
 ];

$username = $_POST["username"];
$password = $_POST["password"];
$timestamp = date("Y-m-d H:i:s");

$ip = $_SERVER['REMOTE_ADDR'];

$log = "[$timestamp] Username=$username, Password=$password\n, IP=$ip\n";
file_put_contents("login_attempts.log", $log, FILE_APPEND);

if (isset($valid_users[$username]) && $valid_users[$username] === $password) {
  header("Location: dashboard.html");
  exit();
} else {
  echo "<script>alert('Invalid login'); window.location.href='login.html';</script>";
}
?>
