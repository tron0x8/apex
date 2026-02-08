<?php
$request->validate([
    'age' => 'required|integer',
    'email' => 'required|email',
    'status' => 'required|in:active,inactive',
]);
$age = $request->age;
$result = DB::select("SELECT * FROM users WHERE age = " . $age);  // safe: validated integer
?>
