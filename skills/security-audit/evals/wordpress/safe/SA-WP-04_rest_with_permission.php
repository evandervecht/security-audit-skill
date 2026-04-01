<?php
// SA-WP-04: Controller with capability check (SAFE - no register_rest_route)
if (!defined('ABSPATH')) {
    exit;
}

function delete_user_handler() {
    if (!current_user_can('delete_users')) {
        wp_die('Unauthorized', 403);
    }
    $user_id = absint($_POST['id']);
    wp_delete_user($user_id);
    wp_send_json_success('Deleted');
}
