<?php
// SA-WP-03: Unescaped variable in output (VULNERABLE)
function render_profile($user) {
    echo $user->display_name;
    echo '<a href="' . $user->website . '">' . $user->bio . '</a>';
}
