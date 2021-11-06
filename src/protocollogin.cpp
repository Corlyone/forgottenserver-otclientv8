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

#include "protocollogin.h"

#include "outputmessage.h"
#include "tasks.h"

#include "configmanager.h"
#include "iologindata.h"
#include "ban.h"
#include "game.h"

extern ConfigManager g_config;
extern Game g_game;

void ProtocolLogin::disconnectClient(const std::string& message, uint16_t)
{
	auto output = OutputMessagePool::getOutputMessage();

	output->addByte(0x0A);
	output->addString(message);
	send(output);

	disconnect();
}

void ProtocolLogin::getCharacterList(uint32_t accountNumber, const std::string& password, uint16_t version)
{
	Account account;
	if (!IOLoginData::loginserverAuthentication(accountNumber, password, account)) {
		disconnectClient("Account name or password is not correct.", version);
		return;
	}


	auto output = OutputMessagePool::getOutputMessage();

	//Update premium days
	Game::updatePremium(account);

	const std::string& motd = g_config.getString(ConfigManager::MOTD);
	if (!motd.empty()) {
		//Add MOTD
		output->addByte(0x14);

		std::ostringstream ss;
		ss << g_game.getMotdNum() << "\n" << motd;
		output->addString(ss.str());
	}

	//Add char list
	output->addByte(0x64);

	uint8_t size = std::min<size_t>(std::numeric_limits<uint8_t>::max(), account.characters.size());

	output->addByte(size);
	for (uint8_t i = 0; i < size; i++) {
		output->addString(account.characters[i]);
		output->addString(g_config.getString(ConfigManager::SERVER_NAME));
		output->add<uint32_t>(g_config.getNumber(ConfigManager::IP));
		output->add<uint16_t>(g_config.getNumber(ConfigManager::GAME_PORT));
	}

	//Add premium days
	if (g_config.getBoolean(ConfigManager::FREE_PREMIUM)) {
		output->add<uint16_t>(0xFFFF); //client displays free premium
	} else {
		output->add<uint16_t>(account.premiumDays);
	}

	send(output);

	disconnect();
}
//Live Cast
void ProtocolLogin::getCastList(const std::string& password, uint16_t version)
{
	// dispatcher thread
	std::vector<std::string> worldList; // dummy world list to spectators amount; 
	std::vector<std::string> castList;

	uint8_t size = 0;

	for (auto it : ProtocolGame::liveCasts) {
		auto player = it.first;
		auto protocol = it.second;

		if (player && protocol && (password.empty() || protocol->canJoinCast(password))) {
			castList.push_back(player->getName());
			worldList.push_back(std::to_string(protocol->getSpectatorsCount()) + " spectators");
		}

		if (++size == std::numeric_limits<uint8_t>::max()) {
			break;
		}
	}

	// this is a result of incorrect password
	if (castList.empty()) {
		disconnectClient("There is not live cast with this password.", version);
		return;
	}

	auto output = OutputMessagePool::getOutputMessage();

	//Add session key
	output->addByte(0x28);
	output->addString(password);

	//Add char list
	output->addByte(0x64);

	output->addByte(size);
	for (int i = 0; i < size; i++) {
		output->addByte(i); // world id
		output->addString(worldList[i]);
		output->addString(g_config.getString(ConfigManager::IP_STRING));
		output->add<uint16_t>(g_config.getNumber(ConfigManager::CAST_PORT));
		output->addByte(0);
	}

	output->addByte(size);
	for (uint8_t i = 0; i < size; i++) {
		output->addByte(0);
		output->addString(castList[i]);
	}

	// premium;
	output->addByte(0);
	output->addByte(1);
	output->add<uint32_t>(0);

	send(output);

	disconnect();
}

void ProtocolLogin::onRecvFirstMessage(NetworkMessage& msg)
{
	if (g_game.getGameState() == GAME_STATE_SHUTDOWN) {
		disconnect();
		return;
	}

	msg.skipBytes(2); // client OS
	uint16_t version = msg.get<uint16_t>();
	/*
	 * Skipped bytes:
	 * 12 bytes: dat, spr, pic signatures (4 bytes each)
	 */
	 msg.skipBytes(12);

	if (version < 760) {
		std::ostringstream ss;
		ss << "Only clients with protocol " << CLIENT_VERSION_STR << " allowed!";
		disconnectClient(ss.str(), version);
		return;
	}

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

	if (version < CLIENT_VERSION_MIN || version > CLIENT_VERSION_MAX) {
		std::ostringstream ss;
		ss << "Only clients with protocol " << CLIENT_VERSION_STR << " allowed!";
		disconnectClient(ss.str(), version);
		return;
	}

	if (g_game.getGameState() == GAME_STATE_STARTUP) {
		disconnectClient("Gameworld is starting up. Please wait.", version);
		return;
	}

	if (g_game.getGameState() == GAME_STATE_MAINTAIN) {
		disconnectClient("Gameworld is under maintenance.\nPlease re-connect in a while.", version);
		return;
	}

	BanInfo banInfo;
	auto connection = getConnection();
	if (!connection) {
		return;
	}

	if (IOBan::isIpBanned(connection->getIP(), banInfo)) {
		if (banInfo.reason.empty()) {
			banInfo.reason = "(none)";
		}

		std::ostringstream ss;
		ss << "Your IP has been banned until " << formatDateShort(banInfo.expiresAt) << " by " << banInfo.bannedBy << ".\n\nReason specified:\n" << banInfo.reason;
		disconnectClient(ss.str(), version);
		return;
	}

	uint32_t accountNumber = msg.get<uint32_t>();
	std::string password = msg.getString();
	if (accountNumber == 0) {
		if (g_config.getBoolean(ConfigManager::LIVE_CAST_ENABLED)) {
			if (ProtocolGame::liveCasts.empty()) {
				disconnectClient("There are no live casts right now.", version);
			} else {
				auto thisPtr = std::static_pointer_cast<ProtocolLogin>(shared_from_this());
				g_dispatcher.addTask(createTask(std::bind(&ProtocolLogin::getCastList, thisPtr, password, version)));
			}
		} else {
			disconnectClient("Invalid account number.", version);
		}
		return;
	}
	
		if (password.empty()) {
		disconnectClient("Invalid password.", version);
		return;

	// OTCv8 version detection
	uint16_t otclientV8 = 0;
	uint16_t otcV8StringLength = msg.get<uint16_t>();
	if(otcV8StringLength == 5 && msg.getString(5) == "OTCv8") {
		otclientV8 = msg.get<uint16_t>(); // 253, 260, 261, ...
	}

	auto thisPtr = std::static_pointer_cast<ProtocolLogin>(shared_from_this());
	g_dispatcher.addTask(createTask(std::bind(&ProtocolLogin::getCharacterList, thisPtr, accountNumber, password, version)));
}
}
