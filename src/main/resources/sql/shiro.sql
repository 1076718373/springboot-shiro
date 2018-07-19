-- --------------------------------------------------------
-- 主机:                           127.0.0.1
-- 服务器版本:                        5.5.28 - MySQL Community Server (GPL)
-- 服务器操作系统:                      Win64
-- HeidiSQL 版本:                  9.3.0.4984
-- --------------------------------------------------------

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET NAMES utf8mb4 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;

-- 导出 shiro 的数据库结构
CREATE DATABASE IF NOT EXISTS `shiro` /*!40100 DEFAULT CHARACTER SET latin1 */;
USE `shiro`;


-- 导出  表 shiro.permission 结构
CREATE TABLE IF NOT EXISTS `permission` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `url` varchar(256) DEFAULT NULL COMMENT 'url地址',
  `pName` varchar(64) DEFAULT NULL COMMENT 'url描述',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=23 DEFAULT CHARSET=utf8;

-- 正在导出表  shiro.permission 的数据：~2 rows (大约)
/*!40000 ALTER TABLE `permission` DISABLE KEYS */;
REPLACE INTO `permission` (`id`, `url`, `pName`) VALUES
	(21, 'add', '添加用户'),
	(22, 'delete', '删除用户');
/*!40000 ALTER TABLE `permission` ENABLE KEYS */;


-- 导出  表 shiro.role 结构
CREATE TABLE IF NOT EXISTS `role` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `roleName` varchar(32) DEFAULT NULL COMMENT '角色名称',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8;

-- 正在导出表  shiro.role 的数据：~1 rows (大约)
/*!40000 ALTER TABLE `role` DISABLE KEYS */;
REPLACE INTO `role` (`id`, `roleName`) VALUES
	(5, '管理员');
/*!40000 ALTER TABLE `role` ENABLE KEYS */;


-- 导出  表 shiro.role_permission 结构
CREATE TABLE IF NOT EXISTS `role_permission` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `rid` bigint(20) DEFAULT NULL COMMENT '角色ID',
  `pid` bigint(20) DEFAULT NULL COMMENT '权限ID',
  PRIMARY KEY (`id`),
  KEY `FK_role_permission_role` (`rid`),
  KEY `FK_role_permission_permission` (`pid`),
  CONSTRAINT `FK_role_permission_role` FOREIGN KEY (`rid`) REFERENCES `role` (`id`),
  CONSTRAINT `FK_role_permission_permission` FOREIGN KEY (`pid`) REFERENCES `permission` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8;

-- 正在导出表  shiro.role_permission 的数据：~2 rows (大约)
/*!40000 ALTER TABLE `role_permission` DISABLE KEYS */;
REPLACE INTO `role_permission` (`id`, `rid`, `pid`) VALUES
	(1, 5, 21),
	(2, 5, 22);
/*!40000 ALTER TABLE `role_permission` ENABLE KEYS */;


-- 导出  表 shiro.user 结构
CREATE TABLE IF NOT EXISTS `user` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `userName` varchar(20) DEFAULT NULL COMMENT '用户昵称',
  `passWord` varchar(32) DEFAULT NULL COMMENT '密码',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=20 DEFAULT CHARSET=utf8;

-- 正在导出表  shiro.user 的数据：~4 rows (大约)
/*!40000 ALTER TABLE `user` DISABLE KEYS */;
REPLACE INTO `user` (`id`, `userName`, `passWord`) VALUES
	(15, 'sandy', 'aef8bf6539043d132f69bd21758b6fff'),
	(16, 'huang', '8712df79ff2ec6d06bb41a4014086da0'),
	(18, 'hmb', '5b66d9d2c2a445198ccfda826ce6db93'),
	(19, 'qqq', 'bf6cfc3732dec202cd2ad1409a23ba15');
/*!40000 ALTER TABLE `user` ENABLE KEYS */;


-- 导出  表 shiro.user_role 结构
CREATE TABLE IF NOT EXISTS `user_role` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `uid` bigint(20) DEFAULT NULL COMMENT '用户ID',
  `rid` bigint(20) DEFAULT NULL COMMENT '角色ID',
  PRIMARY KEY (`id`),
  KEY `FK_user_role_user` (`uid`),
  KEY `FK_user_role_role` (`rid`),
  CONSTRAINT `FK_user_role_user` FOREIGN KEY (`uid`) REFERENCES `user` (`id`),
  CONSTRAINT `FK_user_role_role` FOREIGN KEY (`rid`) REFERENCES `role` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8;

-- 正在导出表  shiro.user_role 的数据：~1 rows (大约)
/*!40000 ALTER TABLE `user_role` DISABLE KEYS */;
REPLACE INTO `user_role` (`id`, `uid`, `rid`) VALUES
	(1, 15, 5);
/*!40000 ALTER TABLE `user_role` ENABLE KEYS */;
/*!40101 SET SQL_MODE=IFNULL(@OLD_SQL_MODE, '') */;
/*!40014 SET FOREIGN_KEY_CHECKS=IF(@OLD_FOREIGN_KEY_CHECKS IS NULL, 1, @OLD_FOREIGN_KEY_CHECKS) */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
