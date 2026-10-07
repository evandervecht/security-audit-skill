<?php
// SA-JOOMLA-01: JInput with type-specific filter and bound parameter (SAFE)
use Joomla\CMS\Factory;
use Joomla\Database\DatabaseInterface;

class MyModelSafe
{
    private DatabaseInterface $db;

    public function __construct(DatabaseInterface $db)
    {
        $this->db = $db;
    }

    public function search()
    {
        $app = Factory::getApplication();
        $search = $app->input->getString('search');
        $search = '%' . $search . '%';

        $query = $this->db->getQuery(true);
        $query->select('*')
            ->from($this->db->quoteName('#__content'))
            ->where($this->db->quoteName('title') . ' LIKE :search')
            ->bind(':search', $search);

        $this->db->setQuery($query);
        return $this->db->loadObjectList();
    }
}
