/**
 * The Forgotten Server - a free and open-source MMORPG server emulator
 * Copyright (C) 2019  Mark Samman <mark.samman@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "otpch.h"

#include <boost/range/adaptor/reversed.hpp>

#include "protocolgame.h"

#include "outputmessage.h"

#include "player.h"

#include "configmanager.h"
#include "actions.h"
#include "game.h"
#include "iologindata.h"
#include "iomarket.h"
#include "waitlist.h"
#include "ban.h"
#include "scheduler.h"

LiveCastsMap ProtocolGame::liveCasts;

extern ConfigManager g_config;
extern Actions actions;
extern CreatureEvents* g_creatureEvents;
extern Chat* g_chat;

void ProtocolGame::release()
{
	//dispatcher thread
	if (player && player->client == shared_from_this()) {

		// in the dispatcher thread, this should release the protocol after the player is null and this protocol has released
		// so we must exclude every spectator before releasing
		if (isLiveCasting()) {
			sendChannelEvent(CHANNEL_CAST, player->name, CHANNELEVENT_EXCLUDE);
			for (auto spectator : castinfo.spectators) {
				sendChannelEvent(CHANNEL_CAST, spectator->name, CHANNELEVENT_EXCLUDE); // which is gonna be sent to every spectator
			}

			stopLiveCasting();
		}

		player->client.reset();
		player->decrementReferenceCounter();
		player = nullptr;
	}

	OutputMessagePool::getInstance().removeProtocolFromAutosend(shared_from_this());
	Protocol::release();
}

void ProtocolGame::login(const std::string& name, uint32_t accountId, OperatingSystem_t operatingSystem)
{
	// OTCv8 features and extended opcodes
	if (otclientV8 || operatingSystem >= CLIENTOS_OTCLIENT_LINUX) {
		if(otclientV8)
			sendFeatures();
		NetworkMessage opcodeMessage;
		opcodeMessage.addByte(0x32);
		opcodeMessage.addByte(0x00);
		opcodeMessage.add<uint16_t>(0x00);
		writeToOutputBuffer(opcodeMessage);
	}

	//dispatcher thread
	Player* foundPlayer = g_game.getPlayerByName(name);
	if (!foundPlayer || g_config.getBoolean(ConfigManager::ALLOW_CLONES)) {
		player = new Player(getThis());
		player->setName(name);

		player->incrementReferenceCounter();
		player->setID();

		if (!IOLoginData::preloadPlayer(player, name)) {
			disconnectClient("Your character could not be loaded.");
			return;
		}

		if (IOBan::isPlayerNamelocked(player->getGUID())) {
			disconnectClient("Your character has been namelocked.");
			return;
		}

		if (g_game.getGameState() == GAME_STATE_CLOSING && !player->hasFlag(PlayerFlag_CanAlwaysLogin)) {
			disconnectClient("The game is just going down.\nPlease try again later.");
			return;
		}

		if (g_game.getGameState() == GAME_STATE_CLOSED && !player->hasFlag(PlayerFlag_CanAlwaysLogin)) {
			disconnectClient("Server is currently closed.\nPlease try again later.");
			return;
		}

		if (g_config.getBoolean(ConfigManager::ONE_PLAYER_ON_ACCOUNT) && player->getAccountType() < ACCOUNT_TYPE_GAMEMASTER && g_game.getPlayerByAccount(player->getAccount())) {
			disconnectClient("You may only login with one character\nof your account at the same time.");
			return;
		}

		if (!player->hasFlag(PlayerFlag_CannotBeBanned)) {
			BanInfo banInfo;
			if (IOBan::isAccountBanned(accountId, banInfo)) {
				if (banInfo.reason.empty()) {
					banInfo.reason = "(none)";
				}

				std::ostringstream ss;
				if (banInfo.expiresAt > 0) {
					ss << "Your account has been banned until " << formatDateShort(banInfo.expiresAt) << " by " << banInfo.bannedBy << ".\n\nReason specified:\n" << banInfo.reason;
				} else {
					ss << "Your account has been permanently banned by " << banInfo.bannedBy << ".\n\nReason specified:\n" << banInfo.reason;
				}
				disconnectClient(ss.str());
				return;
			}
		}

		std::size_t currentSlot = WaitingList::getInstance().clientLogin(player);
		if (currentSlot > 0) {
			uint8_t retryTime = WaitingList::getTime(currentSlot);
			std::ostringstream ss;

			ss << "Too many players online.\nYou are at place "
			   << currentSlot << " on the waiting list.";

			auto output = OutputMessagePool::getOutputMessage();
			output->addByte(0x16);
			output->addString(ss.str());
			output->addByte(retryTime);
			send(output);
			disconnect();
			return;
		}

		if (!IOLoginData::loadPlayerById(player, player->getGUID())) {
			disconnectClient("Your character could not be loaded.");
			return;
		}

		player->setOperatingSystem(operatingSystem);

		if (!g_game.placeCreature(player, player->getLoginPosition())) {
			if (!g_game.placeCreature(player, player->getTemplePosition(), false, true)) {
				disconnectClient("Temple position is wrong. Contact the administrator.");
				return;
			}
		}
		player->autoOpenContainers();

		if (operatingSystem >= CLIENTOS_OTCLIENT_LINUX) {
			player->registerCreatureEvent("ExtendedOpcode");
		}

		player->lastIP = player->getIP();
		player->lastLoginSaved = std::max<time_t>(time(nullptr), player->lastLoginSaved + 1);
		acceptPackets = true;
	} else {
		if (eventConnect != 0 || !g_config.getBoolean(ConfigManager::REPLACE_KICK_ON_LOGIN)) {
			//Already trying to connect
			disconnectClient("You are already logged in.");
			return;
		}

		if (foundPlayer->client) {
			foundPlayer->disconnect();
			foundPlayer->isConnecting = true;

			eventConnect = g_scheduler.addEvent(createSchedulerTask(1000, std::bind(&ProtocolGame::connect, getThis(), foundPlayer->getID(), operatingSystem)));
		} else {
			connect(foundPlayer->getID(), operatingSystem);
		}
	}
	OutputMessagePool::getInstance().addProtocolToAutosend(shared_from_this());
}

void ProtocolGame::sendChannelEvent(uint16_t channelId, const std::string& playerName, ChannelEvent_t channelEvent)
{
	NetworkMessage msg;
	msg.addByte(0xF3);
	msg.add<uint16_t>(channelId);
	msg.addString(playerName);
	msg.addByte(channelEvent);
	writeToOutputBuffer(msg);
}

void ProtocolGame::connect(uint32_t playerId, OperatingSystem_t operatingSystem)
{
	eventConnect = 0;

	Player* foundPlayer = g_game.getPlayerByID(playerId);
	if (!foundPlayer || foundPlayer->client) {
		disconnectClient("You are already logged in.");
		return;
	}

	if (isConnectionExpired()) {
		//ProtocolGame::release() has been called at this point and the Connection object
		//no longer exists, so we return to prevent leakage of the Player.
		return;
	}

	player = foundPlayer;
	player->incrementReferenceCounter();

	g_chat->removeUserFromAllChannels(*player);
	player->clearModalWindows();
	player->setOperatingSystem(operatingSystem);
	player->isConnecting = false;

	player->client = getThis();
	sendAddCreature(player, player->getPosition(), 0, false);
	player->autoOpenContainers();
	player->lastIP = player->getIP();
	player->lastLoginSaved = std::max<time_t>(time(nullptr), player->lastLoginSaved + 1);
	acceptPackets = true;
}

void ProtocolGame::logout(bool displayEffect, bool forced)
{
	//dispatcher thread
	if (!player) {
		return;
	}

	if (!player->isRemoved()) {
		if (!forced) {
			if (!player->isAccessPlayer()) {
				if (player->getTile()->hasFlag(TILESTATE_NOLOGOUT)) {
					player->sendCancelMessage(RETURNVALUE_YOUCANNOTLOGOUTHERE);
					return;
				}

				if (!player->getTile()->hasFlag(TILESTATE_PROTECTIONZONE) && player->hasCondition(CONDITION_INFIGHT)) {
					player->sendCancelMessage(RETURNVALUE_YOUMAYNOTLOGOUTDURINGAFIGHT);
					return;
				}
			}

			//scripting event - onLogout
			if (!g_creatureEvents->playerLogout(player)) {
				//Let the script handle the error message
				return;
			}
		}

		if (displayEffect && player->getHealth() > 0) {
			g_game.addMagicEffect(player->getPosition(), CONST_ME_POFF);
		}
	}

	disconnect();

	g_game.removeCreature(player);
}

void ProtocolGame::onRecvFirstMessage(NetworkMessage& msg)
{
	if (g_game.getGameState() == GAME_STATE_SHUTDOWN) {
		disconnect();
		return;
	}

	OperatingSystem_t operatingSystem = static_cast<OperatingSystem_t>(msg.get<uint16_t>());
	version = msg.get<uint16_t>();

	if (!Protocol::RSA_decrypt(msg)) {
		disconnect();
		return;
	}

	xtea::key key;
	key[0] = msg.get<uint32_t>();
	key[1] = msg.get<uint32_t>();
	key[2] = msg.get<uint32_t>();
	key[3] = msg.get<uint32_t>();
	enableXTEAEncryption();
	setXTEAKey(std::move(key));

	msg.skipBytes(1); // gamemaster flag

	uint32_t accountNumber = msg.get<uint32_t>();
	if (accountNumber == 0) {
		disconnectClient("You must enter your account number.");
		return;
	}

	std::string characterName = msg.getString();

	std::string password = msg.getString();

	// OTCv8 version detection
	uint16_t otcV8StringLength = msg.get<uint16_t>();
	if(otcV8StringLength == 5 && msg.getString(5) == "OTCv8") {
		otclientV8 = msg.get<uint16_t>(); // 253, 260, 261, ...
	}

	if (version < CLIENT_VERSION_MIN || version > CLIENT_VERSION_MAX) {
		std::ostringstream ss;
		ss << "Only clients with protocol " << CLIENT_VERSION_STR << " allowed!";
		disconnectClient(ss.str());
		return;
	}

	if (g_game.getGameState() == GAME_STATE_STARTUP) {
		disconnectClient("Gameworld is starting up. Please wait.");
		return;
	}

	if (g_game.getGameState() == GAME_STATE_MAINTAIN) {
		disconnectClient("Gameworld is under maintenance. Please re-connect in a while.");
		return;
	}

	BanInfo banInfo;
	if (IOBan::isIpBanned(getIP(), banInfo)) {
		if (banInfo.reason.empty()) {
			banInfo.reason = "(none)";
		}

		std::ostringstream ss;
		ss << "Your IP has been banned until " << formatDateShort(banInfo.expiresAt) << " by " << banInfo.bannedBy << ".\n\nReason specified:\n" << banInfo.reason;
		disconnectClient(ss.str());
		return;
	}

	uint32_t accountId = IOLoginData::gameworldAuthentication(accountNumber, password, characterName);
	if (accountId == 0) {
		disconnectClient("Account name or password is not correct.");
		return;
	}

	g_dispatcher.addTask(createTask(std::bind(&ProtocolGame::login, getThis(), characterName, accountId, operatingSystem)));
}

void ProtocolGame::writeToSpectatorsOutputBuffer(const NetworkMessage& msg)
{
	// dispatcher thread
	if (castinfo.spectators.size() > 0) {
		for(auto spectator : castinfo.spectators) {
			if (spectator) {
				spectator->writeToOutputBuffer(msg);
			}
		}
	}
}

void ProtocolGame::writeToOutputBuffer(const NetworkMessage& msg, bool broadcast/* = true*/)
{
		if (broadcast) {
		g_dispatcher.addTask(createTask(std::bind(&ProtocolGame::writeToSpectatorsOutputBuffer, this, msg)));
	}

	auto out = getOutputBuffer(msg.getLength());
	out->append(msg);
}

void ProtocolGame::parsePacket(NetworkMessage& msg)
{
	if (!acceptPackets || g_game.getGameState() == GAME_STATE_SHUTDOWN || msg.getLength() <= 0) {
		return;
	}

	uint8_t recvbyte = msg.getByte();

	if (!player) {
		if (recvbyte == 0x0F) {
			disconnect();
		}

		return;
	}

	//a dead player can not performs actions
	if (player->isRemoved() || player->getHealth() <= 0) {
		if (recvbyte == 0x0F) {
			disconnect();
			return;
		}

		if (recvbyte != 0x14) {
			return;
		}
	}

	switch (recvbyte) {
		case 0x14: g_dispatcher.addTask(createTask(std::bind(&ProtocolGame::logout, getThis(), true, false))); break;
		case 0x1E: addGameTask(&Game::playerReceivePing, player->getID()); break;
		case 0x32: parseExtendedOpcode(msg); break; //otclient extended opcode
		case 0x40: parseNewPing(msg); break;
		case 0x42: parseChangeAwareRange(msg); break;
		case 0x45: parseNewWalking(msg); break;
		case 0x64: parseAutoWalk(msg); break;
		case 0x65: addGameTask(&Game::playerMove, player->getID(), DIRECTION_NORTH); break;
		case 0x66: addGameTask(&Game::playerMove, player->getID(), DIRECTION_EAST); break;
		case 0x67: addGameTask(&Game::playerMove, player->getID(), DIRECTION_SOUTH); break;
		case 0x68: addGameTask(&Game::playerMove, player->getID(), DIRECTION_WEST); break;
		case 0x69: addGameTask(&Game::playerStopAutoWalk, player->getID()); break;
		case 0x6A: addGameTask(&Game::playerMove, player->getID(), DIRECTION_NORTHEAST); break;
		case 0x6B: addGameTask(&Game::playerMove, player->getID(), DIRECTION_SOUTHEAST); break;
		case 0x6C: addGameTask(&Game::playerMove, player->getID(), DIRECTION_SOUTHWEST); break;
		case 0x6D: addGameTask(&Game::playerMove, player->getID(), DIRECTION_NORTHWEST); break;
		case 0x6F: addGameTaskTimed(DISPATCHER_TASK_EXPIRATION, &Game::playerTurn, player->getID(), DIRECTION_NORTH); break;
		case 0x70: addGameTaskTimed(DISPATCHER_TASK_EXPIRATION, &Game::playerTurn, player->getID(), DIRECTION_EAST); break;
		case 0x71: addGameTaskTimed(DISPATCHER_TASK_EXPIRATION, &Game::playerTurn, player->getID(), DIRECTION_SOUTH); break;
		case 0x72: addGameTaskTimed(DISPATCHER_TASK_EXPIRATION, &Game::playerTurn, player->getID(), DIRECTION_WEST); break;
		case 0x78: parseThrow(msg); break;
		case 0x7D: parseRequestTrade(msg); break;
		case 0x7E: parseLookInTrade(msg); break;
		case 0x7F: addGameTask(&Game::playerAcceptTrade, player->getID()); break;
		case 0x80: addGameTask(&Game::playerCloseTrade, player->getID()); break;
		case 0x82: parseUseItem(msg); break;
		case 0x83: parseUseItemEx(msg); break;
		case 0x84: parseUseWithCreature(msg); break;
		case 0x85: parseRotateItem(msg); break;
		case 0x87: parseCloseContainer(msg); break;
		case 0x88: parseUpArrowContainer(msg); break;
		case 0x89: parseTextWindow(msg); break;
		case 0x8A: parseHouseWindow(msg); break;
		case 0x8B: parseWrapItem(msg); break;
		case 0x8C: parseLookAt(msg); break;
		case 0x8D: parseLookInBattleList(msg); break;
		case 0x8E: /* join aggression */ break;
		case 0x96: parseSay(msg); break;
		case 0x97: addGameTask(&Game::playerRequestChannels, player->getID()); break;
		case 0x98: parseOpenChannel(msg); break;
		case 0x99: parseCloseChannel(msg); break;
		case 0x9A: parseOpenPrivateChannel(msg); break;
		case 0xA0: parseFightModes(msg); break;
		case 0xA1: parseAttack(msg); break;
		case 0xA2: parseFollow(msg); break;
		case 0xA3: parseInviteToParty(msg); break;
		case 0xA4: parseJoinParty(msg); break;
		case 0xA5: parseRevokePartyInvite(msg); break;
		case 0xA6: parsePassPartyLeadership(msg); break;
		case 0xA7: addGameTask(&Game::playerLeaveParty, player->getID()); break;
		case 0xA8: parseEnableSharedPartyExperience(msg); break;
		case 0xAA: addGameTask(&Game::playerCreatePrivateChannel, player->getID()); break;
		case 0xAB: parseChannelInvite(msg); break;
		case 0xAC: parseChannelExclude(msg); break;
		case 0xBE: addGameTask(&Game::playerCancelAttackAndFollow, player->getID()); break;
		case 0xC9: /* update tile */ break;
		case 0xCA: parseUpdateContainer(msg); break;
		case 0xCC: parseSeekInContainer(msg); break;
		case 0xD2: addGameTask(&Game::playerRequestOutfit, player->getID()); break;
		case 0xD3: parseSetOutfit(msg); break;
		case 0xDC: parseAddVip(msg); break;
		case 0xDD: parseRemoveVip(msg); break;
		case 0xE6: parseBugReport(msg); break;
		case 0xE7: /* thank you */ break;
		case 0xE8: parseDebugAssert(msg); break;
		case 0xF0: addGameTaskTimed(DISPATCHER_TASK_EXPIRATION, &Game::playerShowQuestLog, player->getID()); break;
		case 0xF1: parseQuestLine(msg); break;
		case 0xF2: parseRuleViolationReport(msg); break;
		case 0xF3: /* get object info */ break;
		case 0xF4: parseMarketLeave(); break;
		case 0xF5: parseMarketBrowse(msg); break;
		case 0xF6: parseMarketCreateOffer(msg); break;
		case 0xF7: parseMarketCancelOffer(msg); break;
		case 0xF8: parseMarketAcceptOffer(msg); break;
		case 0xF9: parseModalWindowAnswer(msg); break;

		default:
			// std::cout << "Player: " << player->getName() << " sent an unknown packet header: 0x" << std::hex << static_cast<uint16_t>(recvbyte) << std::dec << "!" << std::endl;
			break;
	}

	if (msg.isOverrun()) {
		disconnect();
	}
}
/*
void ProtocolGame::GetTileDescription(const Tile* tile, NetworkMessage& msg)
{
	Item* ground = tile->getGround();
	if (otclientV8) { // OTCLIENTV8 new walking
		uint16_t groundSpeed = 150;
		// I've noticed that sometimes ground speed was incorrect in otclient,
		// so server just sends 100% correct ground speed
		bool isBlocking = false;
		// if isBlocking is true, next prewalking from this tile will be impossible
		// till server confirmation/rejection, used for teleport or stairs
		if (ground) {
			groundSpeed = (uint16_t)Item::items[ground->getID()].speed;
			if (groundSpeed == 0) {
				groundSpeed = 150;
			}
			// you can uncomment to make walk animation slower when going into stairs, looks cool
			// floor change speed is the same, only animation is slower 
			//if(tile->hasFlag(TILESTATE_FLOORCHANGE))
			//    groundSpeed *= 3;
			if (tile->hasFlag(TILESTATE_FLOORCHANGE) || tile->hasFlag(TILESTATE_TELEPORT))
				isBlocking = true;
		}
		msg.add<uint16_t>(groundSpeed);
		msg.add<uint8_t>(isBlocking ? 1 : 0);
	}

	int32_t count;
	if (ground) {
		msg.addItem(ground);
		count = 1;
	} else {
		count = 0;
	}

	const TileItemVector* items = tile->getItemList();
	if (items) {
		for (auto it = items->getBeginTopItem(), end = items->getEndTopItem(); it != end; ++it) {
			msg.addItem(*it);

			count++;
			if (count == 9 && tile->getPosition() == player->getPosition() && !otclientV8) {
				break;
			} else if (count == 10) {
				return;
			}
		}
	}

	const CreatureVector* creatures = tile->getCreatures();
	if (creatures) {
		bool playerAdded = false;
		for (const Creature* creature : boost::adaptors::reverse(*creatures)) {
			if (!player->canSeeCreature(creature)) {
				continue;
			}

			if (tile->getPosition() == player->getPosition() && count == 9 && !playerAdded && !otclientV8) {
				creature = player;
			}

			if (creature->getID() == player->getID()) {
				playerAdded = true;
			}

			bool known;
			uint32_t removedKnown;
			checkCreatureAsKnown(creature->getID(), known, removedKnown);
			AddCreature(msg, creature, known, removedKnown);

			if (++count == 10) {
				return;
			}
		}
	}

	if (items) {
		for (auto it = items->getBeginDownItem(), end = items->getEndDownItem(); it != end; ++it) {
			msg.addItem(*it);

			if (++count == 10) {
				return;
			}
		}
	}
}

void ProtocolGame::GetMapDescription(int32_t x, int32_t y, int32_t z, int32_t width, int32_t height, NetworkMessage& msg)
{
	int32_t skip = -1;
	int32_t startz, endz, zstep;

	if (z > 7) {
		startz = z - 2;
		endz = std::min<int32_t>(MAP_MAX_LAYERS - 1, z + 2);
		zstep = 1;
	} else {
		startz = 7;
		endz = 0;
		zstep = -1;
	}

	for (int32_t nz = startz; nz != endz + zstep; nz += zstep) {
		GetFloorDescription(msg, x, y, nz, width, height, z - nz, skip);
	}

	if (skip >= 0) {
		msg.addByte(skip);
		msg.addByte(0xFF);
	}
}

void ProtocolGame::GetFloorDescription(NetworkMessage& msg, int32_t x, int32_t y, int32_t z, int32_t width, int32_t height, int32_t offset, int32_t& skip)
{
	for (int32_t nx = 0; nx < width; nx++) {
		for (int32_t ny = 0; ny < height; ny++) {
			Tile* tile = g_game.map.getTile(x + nx + offset, y + ny + offset, z);
			if (tile) {
				if (skip >= 0) {
					msg.addByte(skip);
					msg.addByte(0xFF);
				}

				skip = 0;
				GetTileDescription(tile, msg);
			} else if (skip == 0xFE) {
				msg.addByte(0xFF);
				msg.addByte(0xFF);
				skip = -1;
			} else {
				++skip;
			}
		}
	}
}

void ProtocolGame::checkCreatureAsKnown(uint32_t id, bool& known, uint32_t& removedKnown)
{
	auto result = knownCreatureSet.insert(id);
	if (!result.second) {
		known = true;
		return;
	}

	known = false;

	if (knownCreatureSet.size() > 150) {
		// Look for a creature to remove
		for (auto it = knownCreatureSet.begin(), end = knownCreatureSet.end(); it != end; ++it) {
			Creature* creature = g_game.getCreatureByID(*it);
			if (!canSee(creature)) {
				removedKnown = *it;
				knownCreatureSet.erase(it);
				return;
			}
		}

		// Bad situation. Let's just remove anyone.
		auto it = knownCreatureSet.begin();
		if (*it == id) {
			++it;
		}

		removedKnown = *it;
		knownCreatureSet.erase(it);
	} else {
		removedKnown = 0;
	}
}

bool ProtocolGame::canSee(const Creature* c) const
{
	if (!c || !player || c->isRemoved()) {
		return false;
	}

	if (!player->canSeeCreature(c)) {
		return false;
	}

	return canSee(c->getPosition());
}

bool ProtocolGame::canSee(const Position& pos) const
{
	return canSee(pos.x, pos.y, pos.z);
}

bool ProtocolGame::canSee(int32_t x, int32_t y, int32_t z) const
{
	if (!player) {
		return false;
	}

	const Position& myPos = player->getPosition();
	if (myPos.z <= 7) {
		//we are on ground level or above (7 -> 0)
		//view is from 7 -> 0
		if (z > 7) {
			return false;
		}
	} else if (myPos.z >= 8) {
		//we are underground (8 -> 15)
		//view is +/- 2 from the floor we stand on
		if (std::abs(myPos.getZ() - z) > 2) {
			return false;
		}
	}

	//negative offset means that the action taken place is on a lower floor than ourself
	int32_t offsetz = myPos.getZ() - z;
	if ((x >= myPos.getX() - awareRange.left() + offsetz) && (x <= myPos.getX() + awareRange.right() + offsetz) &&
		(y >= myPos.getY() - awareRange.top() + offsetz) && (y <= myPos.getY() + awareRange.bottom() + offsetz)) {
		return true;
	}
	return false;
}
*/
// Parse methods
void ProtocolGame::parseChannelInvite(NetworkMessage& msg)
{
	const std::string name = msg.getString();
	addGameTask(&Game::playerChannelInvite, player->getID(), name);
}

void ProtocolGame::parseChannelExclude(NetworkMessage& msg)
{
	const std::string name = msg.getString();
	addGameTask(&Game::playerChannelExclude, player->getID(), name);
}

void ProtocolGame::parseOpenChannel(NetworkMessage& msg)
{
	uint16_t channelId = msg.get<uint16_t>();
	addGameTask(&Game::playerOpenChannel, player->getID(), channelId);
}

void ProtocolGame::parseCloseChannel(NetworkMessage& msg)
{
	uint16_t channelId = msg.get<uint16_t>();
	addGameTask(&Game::playerCloseChannel, player->getID(), channelId);
}

void ProtocolGame::parseOpenPrivateChannel(NetworkMessage& msg)
{
	const std::string receiver = msg.getString();
	addGameTask(&Game::playerOpenPrivateChannel, player->getID(), receiver);
}

void ProtocolGame::parseAutoWalk(NetworkMessage& msg)
{
	uint8_t numdirs = msg.getByte();
	if (numdirs == 0 || (msg.getBufferPosition() + numdirs) != (msg.getLength() + 4)) {
		return;
	}

	msg.skipBytes(numdirs);

	std::list<Direction> path;
	for (uint8_t i = 0; i < numdirs; ++i) {
		uint8_t rawdir = msg.getPreviousByte();
		switch (rawdir) {
			case 1: path.push_front(DIRECTION_EAST); break;
			case 2: path.push_front(DIRECTION_NORTHEAST); break;
			case 3: path.push_front(DIRECTION_NORTH); break;
			case 4: path.push_front(DIRECTION_NORTHWEST); break;
			case 5: path.push_front(DIRECTION_WEST); break;
			case 6: path.push_front(DIRECTION_SOUTHWEST); break;
			case 7: path.push_front(DIRECTION_SOUTH); break;
			case 8: path.push_front(DIRECTION_SOUTHEAST); break;
			default: break;
		}
	}

	if (path.empty()) {
		return;
	}

	addGameTask(&Game::playerAutoWalk, player->getID(), path);
}

void ProtocolGame::parseSetOutfit(NetworkMessage& msg)
{
	Outfit_t newOutfit;
	newOutfit.lookType = msg.get<uint16_t>();
	newOutfit.lookHead = msg.getByte();
	newOutfit.lookBody = msg.getByte();
	newOutfit.lookLegs = msg.getByte();
	newOutfit.lookFeet = msg.getByte();
	addGameTask(&Game::playerChangeOutfit, player->getID(), newOutfit);
}

void ProtocolGame::parseUseItem(NetworkMessage& msg)
{
	Position pos = msg.getPosition();
	uint16_t spriteId = msg.get<uint16_t>();
	uint8_t stackpos = msg.getByte();
	uint8_t index = msg.getByte();
	addGameTaskTimed(DISPATCHER_TASK_EXPIRATION, &Game::playerUseItem, player->getID(), pos, stackpos, index, spriteId);
}

void ProtocolGame::parseUseItemEx(NetworkMessage& msg)
{
	Position fromPos = msg.getPosition();
	uint16_t fromSpriteId = msg.get<uint16_t>();
	uint8_t fromStackPos = msg.getByte();
	Position toPos = msg.getPosition();
	uint16_t toSpriteId = msg.get<uint16_t>();
	uint8_t toStackPos = msg.getByte();
	addGameTaskTimed(DISPATCHER_TASK_EXPIRATION, &Game::playerUseItemEx, player->getID(), fromPos, fromStackPos, fromSpriteId, toPos, toStackPos, toSpriteId);
}

void ProtocolGame::parseUseWithCreature(NetworkMessage& msg)
{
	Position fromPos = msg.getPosition();
	uint16_t spriteId = msg.get<uint16_t>();
	uint8_t fromStackPos = msg.getByte();
	uint32_t creatureId = msg.get<uint32_t>();
	addGameTaskTimed(DISPATCHER_TASK_EXPIRATION, &Game::playerUseWithCreature, player->getID(), fromPos, fromStackPos, creatureId, spriteId);
}

void ProtocolGame::parseCloseContainer(NetworkMessage& msg)
{
	uint8_t cid = msg.getByte();
	addGameTask(&Game::playerCloseContainer, player->getID(), cid);
}

void ProtocolGame::parseUpArrowContainer(NetworkMessage& msg)
{
	uint8_t cid = msg.getByte();
	addGameTask(&Game::playerMoveUpContainer, player->getID(), cid);
}

void ProtocolGame::parseUpdateContainer(NetworkMessage& msg)
{
	uint8_t cid = msg.getByte();
	addGameTask(&Game::playerUpdateContainer, player->getID(), cid);
}

void ProtocolGame::parseThrow(NetworkMessage& msg)
{
	Position fromPos = msg.getPosition();
	uint16_t spriteId = msg.get<uint16_t>();
	uint8_t fromStackpos = msg.getByte();
	Position toPos = msg.getPosition();
	uint8_t count = msg.getByte();

	if (toPos != fromPos) {
		addGameTaskTimed(DISPATCHER_TASK_EXPIRATION, &Game::playerMoveThing, player->getID(), fromPos, spriteId, fromStackpos, toPos, count);
	}
}

void ProtocolGame::parseLookAt(NetworkMessage& msg)
{
	Position pos = msg.getPosition();
	msg.skipBytes(2); // spriteId
	uint8_t stackpos = msg.getByte();
	addGameTaskTimed(DISPATCHER_TASK_EXPIRATION, &Game::playerLookAt, player->getID(), pos, stackpos);
}

void ProtocolGame::parseLookInBattleList(NetworkMessage& msg)
{
	uint32_t creatureId = msg.get<uint32_t>();
	addGameTaskTimed(DISPATCHER_TASK_EXPIRATION, &Game::playerLookInBattleList, player->getID(), creatureId);
}

void ProtocolGame::parseSay(NetworkMessage& msg)
{
	std::string receiver;
	uint16_t channelId;

	SpeakClasses type = static_cast<SpeakClasses>(msg.getByte());
	switch (type) {
		case TALKTYPE_PRIVATE:
		case TALKTYPE_PRIVATE_RED:
			receiver = msg.getString();
			channelId = 0;
			break;

		case TALKTYPE_CHANNEL_Y:
		case TALKTYPE_CHANNEL_R1:
		case TALKTYPE_CHANNEL_R2:
			channelId = msg.get<uint16_t>();
			break;

		default:
			channelId = 0;
			break;
	}

	const std::string text = msg.getString();
	if (text.length() > 255) {
		return;
	}

	addGameTask(&Game::playerSay, player->getID(), channelId, type, receiver, text);
}

void ProtocolGame::parseFightModes(NetworkMessage& msg)
{
	uint8_t rawFightMode = msg.getByte(); // 1 - offensive, 2 - balanced, 3 - defensive
	uint8_t rawChaseMode = msg.getByte(); // 0 - stand while fightning, 1 - chase opponent
	uint8_t rawSecureMode = msg.getByte(); // 0 - can't attack unmarked, 1 - can attack unmarked
	
	// uint8_t rawPvpMode = msg.getByte(); // pvp mode introduced in 10.0 -- NOT USED

	fightMode_t fightMode;
	if (rawFightMode == 1) {
		fightMode = FIGHTMODE_ATTACK;
	} else if (rawFightMode == 2) {
		fightMode = FIGHTMODE_BALANCED;
	} else {
		fightMode = FIGHTMODE_DEFENSE;
	}

	addGameTask(&Game::playerSetFightModes, player->getID(), fightMode, rawChaseMode != 0, rawSecureMode != 0);
}

void ProtocolGame::parseAttack(NetworkMessage& msg)
{
	uint32_t creatureId = msg.get<uint32_t>();
	// msg.get<uint32_t>(); creatureId (same as above)
	addGameTask(&Game::playerSetAttackedCreature, player->getID(), creatureId);
}

void ProtocolGame::parseFollow(NetworkMessage& msg)
{
	uint32_t creatureId = msg.get<uint32_t>();
	// msg.get<uint32_t>(); creatureId (same as above)
	addGameTask(&Game::playerFollowCreature, player->getID(), creatureId);
}

void ProtocolGame::parseTextWindow(NetworkMessage& msg)
{
	uint32_t windowTextId = msg.get<uint32_t>();
	const std::string newText = msg.getString();
	addGameTask(&Game::playerWriteItem, player->getID(), windowTextId, newText);
}

void ProtocolGame::parseHouseWindow(NetworkMessage& msg)
{
	uint8_t doorId = msg.getByte();
	uint32_t id = msg.get<uint32_t>();
	const std::string text = msg.getString();
	addGameTask(&Game::playerUpdateHouseWindow, player->getID(), doorId, id, text);
}

void ProtocolGame::parseWrapItem(NetworkMessage& msg)
{
	Position pos = msg.getPosition();
	uint16_t spriteId = msg.get<uint16_t>();
	uint8_t stackpos = msg.getByte();
	addGameTaskTimed(DISPATCHER_TASK_EXPIRATION, &Game::playerWrapItem, player->getID(), pos, stackpos, spriteId);
}

void ProtocolGame::parseRequestTrade(NetworkMessage& msg)
{
	Position pos = msg.getPosition();
	uint16_t spriteId = msg.get<uint16_t>();
	uint8_t stackpos = msg.getByte();
	uint32_t playerId = msg.get<uint32_t>();
	addGameTask(&Game::playerRequestTrade, player->getID(), pos, stackpos, playerId, spriteId);
}

void ProtocolGame::parseLookInTrade(NetworkMessage& msg)
{
	bool counterOffer = (msg.getByte() == 0x01);
	uint8_t index = msg.getByte();
	addGameTaskTimed(DISPATCHER_TASK_EXPIRATION, &Game::playerLookInTrade, player->getID(), counterOffer, index);
}

void ProtocolGame::parseAddVip(NetworkMessage& msg)
{
	const std::string name = msg.getString();
	addGameTask(&Game::playerRequestAddVip, player->getID(), name);
}

void ProtocolGame::parseRemoveVip(NetworkMessage& msg)
{
	uint32_t guid = msg.get<uint32_t>();
	addGameTask(&Game::playerRequestRemoveVip, player->getID(), guid);
}

void ProtocolGame::parseRotateItem(NetworkMessage& msg)
{
	Position pos = msg.getPosition();
	uint16_t spriteId = msg.get<uint16_t>();
	uint8_t stackpos = msg.getByte();
	addGameTaskTimed(DISPATCHER_TASK_EXPIRATION, &Game::playerRotateItem, player->getID(), pos, stackpos, spriteId);
}

void ProtocolGame::parseRuleViolationReport(NetworkMessage& msg)
{
	uint8_t reportType = msg.getByte();
	uint8_t reportReason = msg.getByte();
	const std::string& targetName = msg.getString();
	const std::string& comment = msg.getString();
	std::string translation;
	if (reportType == REPORT_TYPE_NAME) {
		translation = msg.getString();
	} else if (reportType == REPORT_TYPE_STATEMENT) {
		translation = msg.getString();
		msg.get<uint32_t>(); // statement id, used to get whatever player have said, we don't log that.
	}

	addGameTask(&Game::playerReportRuleViolation, player->getID(), targetName, reportType, reportReason, comment, translation);
}

void ProtocolGame::parseBugReport(NetworkMessage& msg)
{
	uint8_t category = msg.getByte();
	std::string message = msg.getString();

	Position position;
	if (category == BUG_CATEGORY_MAP) {
		position = msg.getPosition();
	}

	addGameTask(&Game::playerReportBug, player->getID(), message, position, category);
}

void ProtocolGame::parseDebugAssert(NetworkMessage& msg)
{
	if (debugAssertSent) {
		return;
	}

	debugAssertSent = true;

	std::string assertLine = msg.getString();
	std::string date = msg.getString();
	std::string description = msg.getString();
	std::string comment = msg.getString();
	addGameTask(&Game::playerDebugAssert, player->getID(), assertLine, date, description, comment);
}

void ProtocolGame::parseInviteToParty(NetworkMessage& msg)
{
	uint32_t targetId = msg.get<uint32_t>();
	addGameTask(&Game::playerInviteToParty, player->getID(), targetId);
}

void ProtocolGame::parseJoinParty(NetworkMessage& msg)
{
	uint32_t targetId = msg.get<uint32_t>();
	addGameTask(&Game::playerJoinParty, player->getID(), targetId);
}

void ProtocolGame::parseRevokePartyInvite(NetworkMessage& msg)
{
	uint32_t targetId = msg.get<uint32_t>();
	addGameTask(&Game::playerRevokePartyInvitation, player->getID(), targetId);
}

void ProtocolGame::parsePassPartyLeadership(NetworkMessage& msg)
{
	uint32_t targetId = msg.get<uint32_t>();
	addGameTask(&Game::playerPassPartyLeadership, player->getID(), targetId);
}

void ProtocolGame::parseEnableSharedPartyExperience(NetworkMessage& msg)
{
	bool sharedExpActive = msg.getByte() == 1;
	addGameTask(&Game::playerEnableSharedPartyExperience, player->getID(), sharedExpActive);
}

void ProtocolGame::parseQuestLine(NetworkMessage& msg)
{
	uint16_t questId = msg.get<uint16_t>();
	addGameTask(&Game::playerShowQuestLine, player->getID(), questId);
}

void ProtocolGame::parseMarketLeave()
{
	addGameTask(&Game::playerLeaveMarket, player->getID());
}

void ProtocolGame::parseMarketBrowse(NetworkMessage& msg)
{
	uint16_t browseId = msg.get<uint16_t>();

	if (browseId == MARKETREQUEST_OWN_OFFERS) {
		addGameTask(&Game::playerBrowseMarketOwnOffers, player->getID());
	} else if (browseId == MARKETREQUEST_OWN_HISTORY) {
		addGameTask(&Game::playerBrowseMarketOwnHistory, player->getID());
	} else {
		addGameTask(&Game::playerBrowseMarket, player->getID(), browseId);
	}
}

void ProtocolGame::parseMarketCreateOffer(NetworkMessage& msg)
{
	uint8_t type = msg.getByte();
	uint16_t spriteId = msg.get<uint16_t>();
	uint16_t amount = msg.get<uint16_t>();
	uint32_t price = msg.get<uint32_t>();
	bool anonymous = (msg.getByte() != 0);
	addGameTask(&Game::playerCreateMarketOffer, player->getID(), type, spriteId, amount, price, anonymous);
}

void ProtocolGame::parseMarketCancelOffer(NetworkMessage& msg)
{
	uint32_t timestamp = msg.get<uint32_t>();
	uint16_t counter = msg.get<uint16_t>();
	addGameTask(&Game::playerCancelMarketOffer, player->getID(), timestamp, counter);
}

void ProtocolGame::parseMarketAcceptOffer(NetworkMessage& msg)
{
	uint32_t timestamp = msg.get<uint32_t>();
	uint16_t counter = msg.get<uint16_t>();
	uint16_t amount = msg.get<uint16_t>();
	addGameTask(&Game::playerAcceptMarketOffer, player->getID(), timestamp, counter, amount);
}

void ProtocolGame::parseModalWindowAnswer(NetworkMessage& msg)
{
	uint32_t id = msg.get<uint32_t>();
	uint8_t button = msg.getByte();
	uint8_t choice = msg.getByte();
	addGameTask(&Game::playerAnswerModalWindow, player->getID(), id, button, choice);
}

void ProtocolGame::parseSeekInContainer(NetworkMessage& msg)
{
	uint8_t containerId = msg.getByte();
	uint16_t index = msg.get<uint16_t>();
	addGameTask(&Game::playerSeekInContainer, player->getID(), containerId, index);
}

// Send methods
void ProtocolGame::parseExtendedOpcode(NetworkMessage& msg)
{
	uint8_t opcode = msg.getByte();
	const std::string& buffer = msg.getString();

	// process additional opcodes via lua script event
	addGameTask(&Game::parsePlayerExtendedOpcode, player->getID(), opcode, buffer);
}

void ProtocolGame::sendCastChannel()
{
	NetworkMessage msg;
	msg.addByte(0xAC);

	msg.add<uint16_t>(CHANNEL_CAST);
	msg.addString(CHANNEL_CAST_STR);

	msg.add<uint16_t>(castinfo.spectators.size());

	for (auto it : castinfo.spectators) {
		msg.addString(it->name);
	}

	msg.add<uint16_t>(0x00);
	writeToOutputBuffer(msg, false);
}

// live casting methods
bool ProtocolGame::startLiveCasting(const std::string& password)
{
	if (player->isInGhostMode()) {
		return false;
	}

	if (castinfo.enabled) {
		// paused casts are still not removed from cast lists;
		if (castinfo.paused) {
			// let's re-enable and notify him
			sendChannelMessage("[Cast system]", "You cast is resumed again.", TALKTYPE_CHANNEL_R1, CHANNEL_CAST);
			castinfo(password);
		}

		return false;
	}

	IOLoginData::startCast(player->getGUID(), password);

	ProtocolGame::liveCasts.insert(std::make_pair(player, this));

	castinfo.enabled = true;
	castinfo.password = password;

	sendCastChannel();
	return true;
}

void ProtocolGame::stopLiveCasting()
{
	if (!castinfo.enabled) {
		return;
	}

	IOLoginData::stopCast(player->getGUID());

	sendChannelEvent(CHANNEL_CAST, player->name, CHANNELEVENT_EXCLUDE);
	for (auto spectator : castinfo.spectators) {
		sendChannelEvent(CHANNEL_CAST, spectator->name, CHANNELEVENT_EXCLUDE);
		spectator->disconnect();
	}

	// castinfo.spectators is cleared by disconnecting every spectator in the dispatcher thread
	castinfo.banList.clear();
	castinfo.muteList.clear();

	castinfo.enabled = false;
	castinfo.paused = false;

	ProtocolGame::liveCasts.erase(player);
	sendClosePrivate(CHANNEL_CAST);
}

void ProtocolGame::pauseLiveCasting(const std::string& reason)
{
	if (!castinfo.enabled) {
		return;
	} else if (castinfo.paused) {
		sendChannelMessage("[Cast system]", "Your cast is already paused.", TALKTYPE_CHANNEL_R1, CHANNEL_CAST);
		return;
	}

	for (auto it : castinfo.spectators) {
		it->disconnect();
	}

	castinfo.pause(reason);
	sendChannelMessage("[Cast system]", "You have paused your cast.", TALKTYPE_CHANNEL_R1, CHANNEL_CAST);
	return;
}

bool ProtocolGame::kickCastSpectator(std::string name)
{
	if (!castinfo.enabled) {
		return false;
	}

	for (auto spectator :  castinfo.spectators) {
		if (spectator && strcasecmp(spectator->name.c_str(), name.c_str()) == 0) {
			sendChannelMessage("[Cast system]", spectator->name + " has been kicked out.", TALKTYPE_CHANNEL_R1, CHANNEL_CAST);
			spectator->disconnect();
			return true;
		}
	}

	sendChannelMessage("[Cast system]", "There is no spectator with that name.", TALKTYPE_CHANNEL_R1, CHANNEL_CAST);
	return false;
}

bool ProtocolGame::banCastSpectator(std::string name)
{
	if (!castinfo.enabled) {
		return false;
	}

	for (auto spectator : castinfo.spectators) {
		if (spectator && strcasecmp(spectator->name.c_str(), name.c_str()) == 0) {
			sendChannelMessage("[Cast system]", spectator->name + " has been banned.", TALKTYPE_CHANNEL_R1, CHANNEL_CAST);
			castinfo.banList.insert(std::make_pair(spectator->name, spectator->getIP()));
			spectator->disconnect();
			return true;
		}
	}

	sendChannelMessage("[Cast system]", "There is no spectator with that name.", TALKTYPE_CHANNEL_R1, CHANNEL_CAST);
	return false;
}

bool ProtocolGame::unBanCastSpectator(std::string name)
{
	if (!castinfo.enabled) {
		return false;
	}

	for (auto& it : castinfo.banList) {
		if (strcasecmp(it.first.c_str(), name.c_str()) == 0) {
			sendChannelMessage("[Cast system]", name + " has been un-banned.", TALKTYPE_CHANNEL_R1, CHANNEL_CAST);
			castinfo.banList.erase(it.first);
			return true;
		}
	}

	sendChannelMessage("[Cast system]", "There is no spectator with that name.", TALKTYPE_CHANNEL_R1, CHANNEL_CAST);
	return false;
}

bool ProtocolGame::muteCastSpectator(std::string name)
{
	if (!castinfo.enabled) {
		return false;
	}

	for (auto spectator : castinfo.spectators) {
		if (spectator && strcasecmp(spectator->name.c_str(), name.c_str()) == 0) {
			if (!spectator->isMuted()) {
				sendChannelMessage("[Cast system]", spectator->name + " has been muted.", TALKTYPE_CHANNEL_R1, CHANNEL_CAST);
				castinfo.banList.insert(std::make_pair(spectator->name, spectator->getIP()));
			} else {
				sendChannelMessage("[Cast system]", spectator->name + " is already muted.", TALKTYPE_CHANNEL_R1, CHANNEL_CAST);
			}

			spectator->disconnect();
			return true;
		}
	}

	sendChannelMessage("[Cast system]", "There is no spectator with that name.", TALKTYPE_CHANNEL_R1, CHANNEL_CAST);
	return false;
}

bool ProtocolGame::unMuteCastSpectator(std::string name)
{
	if (!castinfo.enabled) {
		return false;
	}

	for (auto& it : castinfo.muteList) {
		if (strcasecmp(it.first.c_str(), name.c_str()) == 0) {
			sendChannelMessage("[Cast system]", name + " has been un-banned.", TALKTYPE_CHANNEL_R1, CHANNEL_CAST);
			castinfo.muteList.erase(it.first);
			return true;
		}
	}

	sendChannelMessage("[Cast system]", "There is no spectator with that name.", TALKTYPE_CHANNEL_R1, CHANNEL_CAST);
	return false;
}

// OTCv8
void ProtocolGame::sendFeatures()
{
	if(!otclientV8) 
		return;

	std::map<GameFeature, bool> features;
	// place for non-standard OTCv8 features
	features[GameExtendedOpcode] = true;
	features[GameChangeMapAwareRange] = true;
	features[GameNewWalking] = true;
	features[GameEnvironmentEffect] = false; // disable it, useless 2 byte with every tile
	features[GameExtendedClientPing] = true; 
	features[GameItemTooltip] = true; // fully available from version 2.6
	features[GameWingsAndAura] = true;
	features[GameOutfitShaders] = true;

	// packet compression
	// we don't send feature, because feature assumes all packets are compressed
	// if adler32 is enabled then compression can be detected automaticly, just adlre32 must be 0
	if (g_config.getBoolean(ConfigManager::PACKET_COMPRESSION)) {
		enableCompression();
	}

	if(features.empty())
		return;

	auto msg = getOutputBuffer(1024);
	msg->addByte(0x43);
	msg->add<uint16_t>(features.size());
	for(auto& feature : features) {
		msg->addByte((uint8_t)feature.first);
		msg->addByte(feature.second ? 1 : 0);
	}

	send(std::move(getCurrentBuffer())); // send this packet immediately
}
