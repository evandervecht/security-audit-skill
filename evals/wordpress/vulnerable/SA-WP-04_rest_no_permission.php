<?php
// SA-WP-04: REST API route with __return_true permission_callback (VULNERABLE)
add_action('rest_api_init', function () {
    register_rest_route('myplugin/v1', '/users', array(
        'methods'             => 'DELETE',
        'callback'            => 'delete_user_handler',
        'permission_callback' => '__return_true',
    ));
});

function delete_user_handler($request) {
    $user_id = $request->get_param('id');
    wp_delete_user($user_id);
    return new WP_REST_Response('Deleted', 200);
}
