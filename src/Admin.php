<?php namespace BaunPlugin\Admin;

use Baun\Plugin;
use BaunPlugin\Admin\Pages;
use EasyCSRF\EasyCSRF;
use Symfony\Component\HttpFoundation\Session\Session;

class Admin extends Plugin {

	protected $session;
	protected $csrf;
	protected $users;

	private $adminPages;
	private $adminPosts;

	public function init()
	{
		$this->session = new Session();
		$this->session->start();

		$this->csrf = new EasyCSRF(new CustomCSRFSessionProvider($this->session));

		$this->users = $this->config->get('plugins-bauncms-baun-admin-admin.users');

		$this->adminPages = new Pages(
			$this->config,
			$this->session,
			$this->csrf,
			$this->events,
			$this->router,
			$this->theme,
			$this->contentParser
		);
		$this->adminPages->init();

		$this->theme->addPath(dirname(__DIR__) . '/templates');
		$this->events->addListener('baun.getFiles', [$this, 'setupPosts']);
		$this->events->addListener('baun.afterSetupRoutes', [$this, 'setupRoutes']);
	}

	public function setupPosts()
	{
		if ($this->config->get('baun.blog_path')) {
			$this->adminPosts = new Posts(
				$this->config,
				$this->session,
				$this->csrf,
				$this->events,
				$this->router,
				$this->theme,
				$this->contentParser
			);
			$this->adminPosts->init();
		}
	}

	public function setupRoutes()
	{
		$this->router->filter('csrf', function(){
			if (!empty($_POST)) {
				try {
					if (!isset($_POST['token'])) $_POST['token'] = '';
					$this->csrf->check('baun-admin', $_POST['token']);
				}
				catch(Exception $e) {
					die('Error: Invalid token');
				}
			}
		});
		$this->router->filter('users', function(){
			if (empty($this->users)) {
				header('Location: ' . $this->config->get('app.base_url') . '/admin/create-user');
				return false;
			}
		});
		$this->router->filter('auth', function(){
			if (!$this->session->get('logged_in')) {
				header('Location: ' . $this->config->get('app.base_url') . '/admin/login');
				return false;
			}
		});

		$this->router->group(['before' => ['csrf']], function(){
			$this->router->add('GET',  '/admin/create-user', [$this, 'routeCreateUser']);
			$this->router->add('POST', '/admin/create-user', [$this, 'routePostCreateUser']);
		});

		$this->router->group(['before' => ['csrf', 'users']], function(){
			$this->router->add('GET',  '/admin/login', [$this, 'routeLogin']);
			$this->router->add('POST', '/admin/login', [$this, 'routePostLogin']);
		});

		$this->router->group(['before' => ['csrf', 'users', 'auth']], function(){
			$this->router->add('POST', '/admin/upload', [$this, 'routePostUpload']);
		});

		$this->router->group(['before' => ['csrf', 'users', 'auth']], function(){
			$this->router->add('GET', '/admin/logout', [$this, 'routeLogout']);
			$this->router->add('GET', '/admin/users', [$this, 'routeUsers']);
		});

		$this->adminPages->setupRoutes();
		if (isset($this->adminPosts)) {
			$this->adminPosts->setupRoutes();
		}
	}

	public function routeCreateUser()
	{
		$data = $this->getGlobalTemplateData();
		$data['errors'] = $this->session->getFlashBag()->get('error');
		return $this->theme->render('create-user', $data);
	}

	public function routePostCreateUser()
	{
		$data = $this->getGlobalTemplateData();

		$email = isset($_POST['email']) ? $_POST['email'] : null;
		$password = isset($_POST['password']) ? $_POST['password'] : null;

		if (!$email || !$password) {
			$this->session->getFlashBag()->add('error', 'Both an email address and password are required');
			return $this->theme->render('create-user', $data);
		}

		$data['user'] = [
			'email' => $email,
			'password' => password_hash($password, PASSWORD_BCRYPT)
		];

		return $this->theme->render('created-user', $data);
	}

	public function routeLogin()
	{
		$data = $this->getGlobalTemplateData();
		$data['errors'] = $this->session->getFlashBag()->get('error');
		return $this->theme->render('login', $data);
	}

	public function routePostLogin()
	{
		$email = isset($_POST['email']) ? $_POST['email'] : null;
		$password = isset($_POST['password']) ? $_POST['password'] : null;

		if (!$email || !$password) {
			$this->session->getFlashBag()->add('error', 'Both an email address and password are required');
		}
		if (!$this->session->getFlashBag()->has('error') && !isset($this->users[$email])) {
			$this->session->getFlashBag()->add('error', 'No user exists for this email address');
		}
		if (!$this->session->getFlashBag()->has('error') && !isset($this->users[$email]['password'])) {
			$this->session->getFlashBag()->add('error', 'This user has no password set');
		}
		if (!$this->session->getFlashBag()->has('error') && !password_verify($password, $this->users[$email]['password'])) {
			$this->session->getFlashBag()->add('error', 'Invalid password');
		}
		if ($this->session->getFlashBag()->has('error')) {
			return header('Location: ' . $this->config->get('app.base_url') . '/admin/login');
		}

		$this->session->set('logged_in', true);

		return header('Location: ' . $this->config->get('app.base_url') . '/admin');
	}

	public function routeLogout()
	{
		$this->session->clear();
		return header('Location: ' . $this->config->get('app.base_url') . '/admin/login');
	}

	public function routeUsers()
	{
		$data = $this->getGlobalTemplateData();
		$data['users'] = $this->users;
		return $this->theme->render('users', $data);
	}

	public function routePostUpload()
	{
		if (!empty($_FILES)) {
			// Do some simple file verifications before saving the file.  These
			// checks could be more thorough, but as this is only permitted for
			// authorized users, we don't perform some of the complex checks
			$error = '';
			$fileName = $_FILES['file']['name'];
			$ext = strtolower(end(explode(".",implode("",explode("\\",$fileName)))));
			$mimetype = mime_content_type($_FILES['file']['tmp_name']);
			if ($_FILES['file']['postError'] > 0){
				$phpFileUploadErrors = array(
					1 => 'The uploaded file exceeds the upload_max_filesize directive in php.ini',
					2 => 'The uploaded file exceeds the MAX_FILE_SIZE directive that was specified in the HTML form',
					3 => 'The uploaded file was only partially uploaded',
					4 => 'No file was uploaded',
					6 => 'Missing a temporary folder',
					7 => 'Failed to write file to disk.',
					8 => 'A PHP extension stopped the file upload.',
				);
				$error = $phpFileUploadErrors[$file['postError']];
			}
			elseif ($_FILES['file']['size'] <= 0){
				$error = "File was 0 bytes in length, could have exceeded php upload limit.";
			}
			elseif (!in_array($ext, array('jpg', 'jpeg', 'png', 'gif', 'tiff', 'bmp', 'svg'))){
				$error = "File extension $ext is not a permitted type.";
			}
			elseif (!preg_match("/image\//i", $mimetype))
			{
				$error = "Mime-type $mimetype is not permitted.";
			}
			if ($error != ''){
				http_response_code(400);
				$ret = $error;
			}
			else {
				$ds = DIRECTORY_SEPARATOR;
				$tempFile = $_FILES['file']['tmp_name'];
				$targetFile = BASE_PATH . 'public' . $ds . 'img' . $ds . $fileName;
				move_uploaded_file($tempFile,$targetFile);
				$ret = $this->config->get('app.base_url') . '/img/' . $fileName;
			}
		}
		return $ret;
	}

	protected function getGlobalTemplateData()
	{
		return [
			'base_url' => $this->config->get('app.base_url'),
			'logged_in' => $this->session->get('logged_in'),
			'blog_path' => $this->config->get('baun.blog_path'),
			'current_uri' => $this->router->currentUri(),
			'token' => $this->csrf->generate('baun-admin'),
		];
	}

}
