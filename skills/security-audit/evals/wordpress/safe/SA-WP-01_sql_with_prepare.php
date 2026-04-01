<?php
// SA-WP-01: SQL query with $wpdb->prepare() (SAFE)
if (!defined('ABSPATH')) {
    exit;
}

function get_user_data($user_id) {
    global $wpdb;
    $results = $wpdb->get_results(
        $wpdb->prepare("SELECT * FROM {$wpdb->prefix}users WHERE ID = %d", $user_id)
    );
    return $results;
}
