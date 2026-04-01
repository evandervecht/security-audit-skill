<?php
// SA-DRUPAL-03: Render array with #plain_text (SAFE - no #markup used)
function mymodule_search_page() {
    $query = \Drupal::request()->query->get('q');
    return [
        '#type' => 'html_tag',
        '#tag' => 'h2',
        '#plain_text' => 'Results for: ' . $query,
    ];
}
