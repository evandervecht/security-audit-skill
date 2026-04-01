<?php
// SA-JOOMLA-01: JInput with no filter and direct query concatenation (VULNERABLE)
use Joomla\CMS\Factory;

class MyModelUnsafe
{
    public function search()
    {
        $app = Factory::getApplication();
        $search = $app->input->get('search', '', 'RAW');
        $db = Factory::getDbo();
        $query = $db->getQuery(true);
        $query->select('*')
            ->from('#__content')
            ->where("title LIKE '%" . $search . "%'");
        $db->setQuery($query);
        return $db->loadObjectList();
    }
}
