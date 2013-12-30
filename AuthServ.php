<?php

/*
__PocketMine Plugin__
name=AuthServ
description=Prevents people to impersonate an account, requiring registration and login when connecting.
version=1.1.0-ALPHA
author=JassperBeastHD
class=SimpleAuth
apiversion=9,10,11
*/


//Dont use this plugin without permission from JassperBeastHD!

class SimpleAuth implements Plugin{
	private $api, $server, $config, $sessions, $lastBroadcast = 0;
	public function __construct(ServerAPI $api, $server = false){
		$this->api = $api;
		$this->server = ServerAPI::request();
		$this->sessions = array();
		SimpleAuthAPI::set($this);
	}
	
	public function init(){
		$this->config = new Config($this->api->plugin->configPath($this)."config.yml", CONFIG_YAML, array(
			"allowChat" => false,
			"messageInterval" => 5,
			"timeout" => 120,
			"allowRegister" => true,
			"forceSingleSession" => true,
			"minPasswordLength" => 3,
			"authenticateByLastIP" => true,
		));
		@mkdir($this->api->plugin->configPath($this)."players/");
		if(file_exists($this->api->plugin->configPath($this)."players.yml")){			
			$playerFile = new Config($this->api->plugin->configPath($this)."players.yml", CONFIG_YAML, array());
			console("[INFO] [AuthServ] Importing old format to new format...");
			foreach($playerFile->getAll() as $k => $value){
				@mkdir($this->api->plugin->configPath($this)."players/".$k{0}."/");
				$d = new Config($this->api->plugin->configPath($this)."players/".$k{0}."/".$k.".yml", CONFIG_YAML, $value);
				$d->save();
			}
			@unlink($this->api->plugin->configPath($this)."players.yml");
		}
		
		$this->api->addHandler("player.quit", array($this, "eventHandler"), 50);
		$this->api->addHandler("player.connect", array($this, "eventHandler"), 50);
		$this->api->addHandler("player.spawn", array($this, "eventHandler"), 50);
		$this->api->addHandler("player.respawn", array($this, "eventHandler"), 50);
		$this->api->addHandler("player.chat", array($this, "eventHandler"), 50);
		$this->api->addHandler("console.command", array($this, "eventHandler"), 50);
		$this->api->addHandler("op.check", array($this, "eventHandler"), 50);
		$this->api->addHandler("entity.health.change", array($this, "eventHandler"), 50);
		$this->api->schedule(20, array($this, "checkTimer"), array(), true);
		$this->api->console->register("unregister", "<password>", array($this, "commandHandler"));		
		$this->api->ban->cmdWhitelist("unregister");

		$this->api->console->register("auth", "<command> [parameters...]", array($this, "commandHandler"));
		console("[INFO] AuthServ enabled!");
	}
	
	public function getData($iusername){
		$iusername = strtolower($iusername);
		if(!file_exists($this->api->plugin->configPath($this)."players/".$iusername{0}."/$iusername.yml")){
			return false;
		}
		return new Config($this->api->plugin->configPath($this)."players/".$iusername{0}."/$iusername.yml", CONFIG_YAML, array());
	}
	
	public function commandHandler($cmd, $params, $issuer, $alias){
		$output = "";
		switch($cmd){
			case "auth":
				if(!isset($params[0])){
					$output .= "Usage: /auth <command> [parameters...]\n";
					$output .= "Available commands: help, unregister\n";
				}
				switch(strtolower(array_shift($params))){
					case "unregister":
						if(($player = $this->api->player->get($params[0])) instanceof Player){						
							@unlink($this->api->plugin->configPath($this)."players/".$player->iusername{0}."/".$player->iusername.".yml");
							$this->logout($player);
						}else{
							@unlink($this->api->plugin->configPath($this)."players/".substr(strtolower($params{0}), 0, 1)."/".strtolower($params[0]).".yml");
						}
						break;
					case "help":
					default:
						$output .= "/auth help: Shows this information.\n";
						$output .= "/auth unregister <player>: Removes the player from the database.\n";
				}
				break;
			case "unregister":
				if(!($issuer instanceof Player)){
					$output .= "Please run this command inside the game.\n";
					break;
				}
				if($this->sessions[$issuer->CID] !== true){
					$output .= "Please login first.\n";
					break;
				}
				$d = $this->getData($issuer->iusername);
				if($d !== false and $d->get("hash") === $this->hash($issuer->iusername, implode(" ", $params))){
					unlink($this->api->plugin->configPath($this)."players/".$issuer->iusername{0}."/".$issuer->iusername.".yml");
					$this->logout($issuer);
					$output .= "[AuthServ] Unregistered correctly.\n";
				}else{
					$output .= "[AuthServ] Error during authentication.\n";
				}
				break;
		}
		return $output;
	}
	
	public function checkTimer(){
		if($this->config->get("allowRegister") !== false and ($this->lastBroadcast + $this->config->get("messageInterval")) <= time()){
			$broadcast = true;
			$this->lastBroadcast = time();
		}else{
			$broadcast = false;
		}
		
		if(($timeout = $this->config->get("timeout")) <= 0){
			$timeout = false;
		}
		
		foreach($this->sessions as $CID => $timer){
			if($timer !== true and $timer !== false and isset($this->server->clients[$CID]) and ($this->server->clients[$CID] instanceof Player)){				
				if($broadcast === true){
					$d = $this->getData($this->server->clients[$CID]->iusername);
					if($d === false){					
						$this->server->clients[$CID]->sendChat("[AuthServ] You must register using:\n/register <password>");
					}else{
						$this->server->clients[$CID]->sendChat("[AuthServ] You must authenticate using:\n/login <password>");
					}
				}
				if($timeout !== false and ($timer + $timeout) <= time()){
					$this->server->clients[$CID]->close("authentication timeout");
				}
			}
		}
		
	}
	
	private function hash($salt, $password){
		return bin2hex(hash("sha512", $password . $salt, true) ^ hash("whirlpool", $salt . $password, true));
	}
	
	public function checkLogin(Player $player, $password){
		$d = $this->getData($player->iusername);
		if($d !== false and $d->get("hash") === $this->hash($player->iusername, $password)){
			return true;
		}
		return false;
	}
	
	public function login(Player $player){
		$d = $this->getData($player->iusername);
		if($d !== false){
			$d->set("logindate", time());
			$d->set("lastip", $player->ip);
			$d->save();
		}
		$this->sessions[$player->CID] = true;
		$player->blocked = false;
		$player->entity->setHealth($player->entity->health, "generic");
		$player->sendChat("[AuthServ] You've been authenticated.\n[AuthServ] Thank you for joining.");
		$this->server->handle("simpleauth.login", $player);
		return true;
	}
	
	public function logout(Player $player){
		$this->sessions[$player->CID] = time();
		$player->blocked = true;
		$this->server->handle("simpleauth.logout", $player);
	}
	
	public function register(Player $player, $password){	
		$d = $this->getData($player->iusername);
		if($d === false){
			@mkdir($this->api->plugin->configPath($this)."players/".$player->iusername{0}."/");
			$d = new Config($this->api->plugin->configPath($this)."players/".$player->iusername{0}."/".$player->iusername.".yml", CONFIG_YAML, array());
			$d->set("registerdate", time());
			$d->set("logindate", time());
			$d->set("lastip", $player->ip);
			$d->set("hash", $this->hash($player->iusername, $password));
			$d->save();
			$this->server->handle("auth.register", $player);
			return true;
		}
		return false;
	}
	
	public function eventHandler($data, $event){
		switch($event){
			case "player.quit":
				unset($this->sessions[$data->CID]);
				break;
			case "player.connect":
				$p = $this->api->player->get($data->iusername);
				if($this->config->get("forceSingleSession") === true){
					if(($p instanceof Player) and $p->iusername === $data->iusername){
						return false;
					}
				}
				$this->sessions[$data->CID] = false;
				break;
			case "player.spawn":
				if($this->sessions[$data->CID] !== true){
					$this->sessions[$data->CID] = time();
					$data->blocked = true;
					$data->sendChat("[AuthServ] This is made by JassperBeastHD.");
					if($this->config->get("allowRegister") !== false){
						$d = $this->getData($data->iusername);
						if($this->config->get("authenticateByLastIP") === true and ($d instanceof Config) and $d->get("lastip") == $data->ip){
							$this->login($data);
							break;
						}
						if($d === false){					
							$data->sendChat("[AuthServ] You must register using:\n/register <password>");
						}else{
							$data->sendChat("[AuthServ] You must authenticate using:\n/login <password>");
						}
					}
				}
				break;
			case "entity.health.change":
				if(($data["entity"]->player instanceof Player) and $this->sessions[$data["entity"]->player->CID] !== true){
					return false;
				}
				break;
			case "console.command":
				if(($data["issuer"] instanceof Player) and $this->sessions[$data["issuer"]->CID] !== true){
					if($data["cmd"] === "login" and $this->checkLogin($data["issuer"], implode(" ", $data["parameters"])) === true){
						$this->login($data["issuer"]);
						return true;
					}elseif($data["cmd"] === "register" and strlen(implode(" ", $data["parameters"])) < $this->config->get("minPasswordLength")){
						$data["issuer"]->sendChat("[AuthServ] Your password is too short.\n[AuthServ] Password must be more than 3 word.");
						return true;
					}elseif($this->config->get("allowRegister") !== false and $data["cmd"] === "register" and $this->register($data["issuer"], implode(" ", $data["parameters"])) === true){
						$data["issuer"]->sendChat("[AuthServ] You've been sucesfully registered.\n[AuthServ] Thank you for joining.");
						$this->login($data["issuer"]);
						return true;
					}elseif($data["cmd"] === "login" or $data["cmd"] === "register"){
						$data["issuer"]->sendChat("[AuthServ] Error during authentication.");
						return true;
					}
					return false;
				}
				break;
			case "player.chat":
				if($this->config->get("allowChat") !== true and $this->sessions[$data["player"]->CID] !== true){
					return false;
				}
				break;
			case "op.check":
				$p = $this->api->player->get($data);
				if(($p instanceof Player) and $this->sessions[$p->CID] !== true){
					return false;
				}
				break;
			case "player.respawn":
				if($this->sessions[$data->CID] !== true){
					$data->blocked = true;
				}
				break;
		}
		return;
	}
	
	public function __destruct(){
		$this->config->save();
	}

}

class SimpleAuthAPI{
	private static $object;
	public static function set(SimpleAuth $plugin){
		if(SimpleAuthAPI::$object instanceof SimpleAuth){
			return false;
		}
		SimpleAuthAPI::$object = $plugin;
	}
	
	public static function get(){
		return SimpleAuthAPI::$object;
	}
	
	public static function login(Player $player){
		return SimpleAuthAPI::$object->login($player);
	}
	
	public static function logout(Player $player){
		return SimpleAuthAPI::$object->logout($player);
	}
}
