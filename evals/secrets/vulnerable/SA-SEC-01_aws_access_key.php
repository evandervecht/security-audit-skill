<?php
// Production config — real leaked AWS access key committed to source
$awsKey = "AKIA3F7XQ2MN8PLZK9WD";
$client = new S3Client([
    'region'      => 'eu-west-1',
    'credentials' => ['key' => $awsKey, 'secret' => getenv('AWS_SECRET')],
]);
