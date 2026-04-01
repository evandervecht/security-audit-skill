<?php
// SA-WP-03: Properly escaped output (SAFE)
if (!defined('ABSPATH')) {
    exit;
}

function render_profile($user) {
    echo esc_html($user->display_name);
    echo '<a href="' . esc_url($user->website) . '">' . esc_html($user->bio) . '</a>';
}
