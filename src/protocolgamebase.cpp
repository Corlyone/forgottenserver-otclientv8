/**
 * The Forgotten Server - a free and open-source MMORPG server emulator
 * Copyright (C) 2017  Mark Samman <mark.samman@gmail.com>
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

#include "protocolgamebase.h"

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
#include "walkmatrix.h"

extern ConfigManager g_config;
extern Actions actions;
extern CreatureEvents* g_creatureEvents;
extern Chat* g_chat;

void ProtocolGameBase::release()
{
	//dispatcher thread
	if (player && player->client == shared_from_this()) {
		player->client.reset();
		player->decrementReferenceCounter();
		player = nullptr;
	}

	OutputMessagePool::getInstance().removeProtocolFromAutosend(shared_from_this());
	Protocol::release();
}

void ProtocolGameBase::connect(uint32_t playerId, OperatingSystem_t operatingSystem)
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

void ProtocolGameBase::parsePacket(NetworkMessage& msg)
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
	case 0x7F: addGameTask(&Game::playerAcceptTrade, player->getID()); break;
	case 0x80: addGameTask(&Game::playerCloseTrade, player->getID()); break;
	case 0x8E: /* join aggression */ break;
	case 0x97: addGameTask(&Game::playerRequestChannels, player->getID()); break;
	case 0xA7: addGameTask(&Game::playerLeaveParty, player->getID()); break;
	case 0xAA: addGameTask(&Game::playerCreatePrivateChannel, player->getID()); break;
	case 0xBE: addGameTask(&Game::playerCancelAttackAndFollow, player->getID()); break;
	case 0xD2: addGameTask(&Game::playerRequestOutfit, player->getID()); break;
	case 0xF0: addGameTaskTimed(DISPATCHER_TASK_EXPIRATION, &Game::playerShowQuestLog, player->getID()); break;

	default:
		// std::cout << "Player: " << player->getName() << " sent an unknown packet header: 0x" << std::hex << static_cast<uint16_t>(recvbyte) << std::dec << "!" << std::endl;
		break;
	}

	if (msg.isOverrun()) {
		disconnect();
	}
}

void ProtocolGameBase::disconnectClient(const std::string& message) const
{
	auto output = OutputMessagePool::getOutputMessage();
	output->addByte(0x14);
	output->addString(message);
	send(output);
	disconnect();
}

void ProtocolGameBase::onConnect()
{
	auto output = OutputMessagePool::getOutputMessage();
	static std::random_device rd;
	static std::ranlux24 generator(rd());
	static std::uniform_int_distribution<uint16_t> randNumber(0x00, 0xFF);

	// Skip checksum
	output->skipBytes(sizeof(uint32_t));

	// Packet length & type
	output->add<uint16_t>(0x0006);
	output->addByte(0x1F);

	// Add timestamp & random number
	challengeTimestamp = static_cast<uint32_t>(time(nullptr));
	output->add<uint32_t>(challengeTimestamp);

	challengeRandom = randNumber(generator);
	output->addByte(challengeRandom);

	// Go back and write checksum
	output->skipBytes(-12);
	output->add<uint32_t>(adlerChecksum(output->getOutputBuffer() + sizeof(uint32_t), 8));

	send(output);
}

void ProtocolGameBase::writeToOutputBuffer(const NetworkMessage& msg, bool broadcast)
{
	auto out = getOutputBuffer(msg.getLength());
	out->append(msg);
}

void ProtocolGameBase::GetTileDescription(const Tile* tile, NetworkMessage& msg)
{
	msg.add<uint16_t>(0x00); //environmental effects

	int32_t count;
	Item* ground = tile->getGround();
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

			if (++count == 10) {
				return;
			}
		}
	}

	const CreatureVector* creatures = tile->getCreatures();
	if (creatures) {
		for (const Creature* creature : boost::adaptors::reverse(*creatures)) {
			if (!player->canSeeCreature(creature)) {
				continue;
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

void ProtocolGameBase::GetMapDescription(int32_t x, int32_t y, int32_t z, int32_t width, int32_t height, NetworkMessage& msg)
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

void ProtocolGameBase::GetFloorDescription(NetworkMessage& msg, int32_t x, int32_t y, int32_t z, int32_t width, int32_t height, int32_t offset, int32_t& skip)
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

void ProtocolGameBase::checkCreatureAsKnown(uint32_t id, bool& known, uint32_t& removedKnown)
{
	auto result = knownCreatureSet.insert(id);
	if (!result.second) {
		known = true;
		return;
	}

	known = false;

	if (knownCreatureSet.size() > 1300) {
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

bool ProtocolGameBase::canSee(const Creature* c) const
{
	if (!c || !player || c->isRemoved()) {
		return false;
	}

	if (!player->canSeeCreature(c)) {
		return false;
	}

	return canSee(c->getPosition());
}

bool ProtocolGameBase::canSee(const Position& pos) const
{
	return canSee(pos.x, pos.y, pos.z);
}

bool ProtocolGameBase::canSee(int32_t x, int32_t y, int32_t z) const
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
	if ((x >= myPos.getX() - 8 + offsetz) && (x <= myPos.getX() + 9 + offsetz) &&
	        (y >= myPos.getY() - 6 + offsetz) && (y <= myPos.getY() + 7 + offsetz)) {
		return true;
	}
	return false;
}

// Send methods
void ProtocolGameBase::sendOpenPrivateChannel(const std::string& receiver)
{
	NetworkMessage msg;
	msg.addByte(0xAD);
	msg.addString(receiver);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendChannelEvent(uint16_t channelId, const std::string& playerName, ChannelEvent_t channelEvent, bool broadcast/* = true*/)
{
	NetworkMessage msg;
	msg.addByte(0xF3);
	msg.add<uint16_t>(channelId);
	msg.addString(playerName);
	msg.addByte(channelEvent);
	writeToOutputBuffer(msg, broadcast);
}

void ProtocolGameBase::sendCreatureOutfit(const Creature* creature, const Outfit_t& outfit)
{
	if (!canSee(creature)) {
		return;
	}

	NetworkMessage msg;
	msg.addByte(0x8E);
	msg.add<uint32_t>(creature->getID());
	AddOutfit(msg, outfit);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendCreatureLight(const Creature* creature)
{
	if (!canSee(creature)) {
		return;
	}

	NetworkMessage msg;
	AddCreatureLight(msg, creature);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendWorldLight(const LightInfo& lightInfo)
{
	NetworkMessage msg;
	AddWorldLight(msg, lightInfo);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::AddWorldLight(NetworkMessage& msg, LightInfo lightInfo)
{
	msg.addByte(0x82);
	msg.addByte((player->isAccessPlayer() ? 0xFF : lightInfo.level));
	msg.addByte(lightInfo.color);
}

void ProtocolGameBase::sendCreatureWalkthrough(const Creature* creature, bool walkthrough)
{
	if (!canSee(creature)) {
		return;
	}

	NetworkMessage msg;
	msg.addByte(0x92);
	msg.add<uint32_t>(creature->getID());
	msg.addByte(walkthrough ? 0x00 : 0x01);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendCreatureShield(const Creature* creature)
{
	if (!canSee(creature)) {
		return;
	}

	NetworkMessage msg;
	msg.addByte(0x91);
	msg.add<uint32_t>(creature->getID());
	msg.addByte(player->getPartyShield(creature->getPlayer()));
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendCreatureSkull(const Creature* creature)
{
	if (g_game.getWorldType() != WORLD_TYPE_PVP) {
		return;
	}

	if (!canSee(creature)) {
		return;
	}

	NetworkMessage msg;
	msg.addByte(0x90);
	msg.add<uint32_t>(creature->getID());
	msg.addByte(player->getSkullClient(creature));
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendCreatureType(uint32_t creatureId, uint8_t creatureType)
{
	NetworkMessage msg;
	msg.addByte(0x95);
	msg.add<uint32_t>(creatureId);
	msg.addByte(creatureType);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendCreatureHelpers(uint32_t creatureId, uint16_t helpers)
{
	NetworkMessage msg;
	msg.addByte(0x94);
	msg.add<uint32_t>(creatureId);
	msg.add<uint16_t>(helpers);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendCreatureSquare(const Creature* creature, SquareColor_t color)
{
	if (!canSee(creature)) {
		return;
	}

	NetworkMessage msg;
	msg.addByte(0x93);
	msg.add<uint32_t>(creature->getID());
	msg.addByte(0x01);
	msg.addByte(color);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendTutorial(uint8_t tutorialId)
{
	NetworkMessage msg;
	msg.addByte(0xDC);
	msg.addByte(tutorialId);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendAddMarker(const Position& pos, uint8_t markType, const std::string& desc)
{
	NetworkMessage msg;
	msg.addByte(0xDD);
	msg.addPosition(pos);
	msg.addByte(markType);
	msg.addString(desc);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendReLoginWindow(uint8_t unfairFightReduction)
{
	NetworkMessage msg;
	msg.addByte(0x28);
	msg.addByte(0x00);
	msg.addByte(unfairFightReduction);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendStats()
{
	NetworkMessage msg;
	AddPlayerStats(msg);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendBasicData()
{
	NetworkMessage msg;
	msg.addByte(0x9F);
	if (player->isPremium()) {
		msg.addByte(1);
		msg.add<uint32_t>(time(nullptr) + (player->premiumDays * 86400));
	} else {
		msg.addByte(0);
		msg.add<uint32_t>(0);
	}
	msg.addByte(player->getVocation()->getClientId());
	msg.add<uint16_t>(0xFF); // number of known spells
	for (uint8_t spellId = 0x00; spellId < 0xFF; spellId++) {
		msg.addByte(spellId);
	}
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendTextMessage(const TextMessage& message)
{
	NetworkMessage msg;
	msg.addByte(0xB4);
	msg.addByte(message.type);
	msg.addString(message.text);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendColoredText(const ColoredText& coloredText)
{
	if (!canSee(coloredText.position)) {
		return;
	}

	NetworkMessage msg;
	msg.addByte(0x84);
	msg.addPosition(coloredText.position);
	msg.addByte(coloredText.color);
	msg.addString(coloredText.text);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendClosePrivate(uint16_t channelId)
{
	NetworkMessage msg;
	msg.addByte(0xB3);
	msg.add<uint16_t>(channelId);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendCreatePrivateChannel(uint16_t channelId, const std::string& channelName)
{
	NetworkMessage msg;
	msg.addByte(0xB2);
	msg.add<uint16_t>(channelId);
	msg.addString(channelName);
	msg.add<uint16_t>(0x01);
	msg.addString(player->getName());
	msg.add<uint16_t>(0x00);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendChannelsDialog()
{
	NetworkMessage msg;
	msg.addByte(0xAB);

	const ChannelList& list = g_chat->getChannelList(*player);
	msg.addByte(list.size());
	for (ChatChannel* channel : list) {
		msg.add<uint16_t>(channel->getId());
		msg.addString(channel->getName());
	}

	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendChannel(uint16_t channelId, const std::string& channelName)
{
	NetworkMessage msg;
	msg.addByte(0xAC);
	msg.add<uint16_t>(channelId);
	msg.addString(channelName);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendChannelMessage(const std::string& author, const std::string& text, SpeakClasses type, uint16_t channel)
{
	NetworkMessage msg;
	msg.addByte(0xAA);
	msg.add<uint32_t>(0x00);
	msg.addString(author);
	msg.add<uint16_t>(0x00);
	msg.addByte(type);
	msg.add<uint16_t>(channel);
	msg.addString(text);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendIcons(uint16_t icons)
{
	NetworkMessage msg;
	msg.addByte(0xA2);
	msg.add<uint16_t>(icons);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendContainer(uint8_t cid, const Container* container, bool hasParent, uint16_t firstIndex)
{
	NetworkMessage msg;
	msg.addByte(0x6E);

	msg.addByte(cid);

	msg.addItem(container, otclientV8);
	msg.addString(container->getName());

	msg.addByte(container->capacity());

	msg.addByte(hasParent ? 0x01 : 0x00);

	msg.addByte(container->isUnlocked() ? 0x01 : 0x00); // Drag and drop
	msg.addByte(container->hasPagination() ? 0x01 : 0x00); // Pagination

	uint32_t containerSize = container->size();
	msg.add<uint16_t>(containerSize);
	msg.add<uint16_t>(firstIndex);
	if (firstIndex < containerSize) {
		uint8_t itemsToSend = std::min<uint32_t>(std::min<uint32_t>(container->capacity(), containerSize - firstIndex), std::numeric_limits<uint8_t>::max());

		msg.addByte(itemsToSend);
		for (auto it = container->getItemList().begin() + firstIndex, end = it + itemsToSend; it != end; ++it) {
			msg.addItem(*it);
		}
	} else {
		msg.addByte(0x00);
	}
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendShop(Npc* npc, const ShopInfoList& itemList)
{
	NetworkMessage msg;
	msg.addByte(0x7A);
	msg.addString(npc->getName());

	uint16_t itemsToSend = std::min<size_t>(itemList.size(), std::numeric_limits<uint16_t>::max());
	msg.add<uint16_t>(itemsToSend);

	uint16_t i = 0;
	for (auto it = itemList.begin(); i < itemsToSend; ++it, ++i) {
		AddShopItem(msg, *it);
	}

	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendCloseShop()
{
	NetworkMessage msg;
	msg.addByte(0x7C);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendSaleItemList(const std::list<ShopInfo>& shop)
{
	NetworkMessage msg;
	msg.addByte(0x7B);
	msg.add<uint64_t>(player->getMoney());

	std::map<uint16_t, uint32_t> saleMap;

	if (shop.size() <= 5) {
		// For very small shops it's not worth it to create the complete map
		for (const ShopInfo& shopInfo : shop) {
			if (shopInfo.sellPrice == 0) {
				continue;
			}

			int8_t subtype = -1;

			const ItemType& itemType = Item::items[shopInfo.itemId];
			if (itemType.hasSubType() && !itemType.stackable) {
				subtype = (shopInfo.subType == 0 ? -1 : shopInfo.subType);
			}

			uint32_t count = player->getItemTypeCount(shopInfo.itemId, subtype);
			if (count > 0) {
				saleMap[shopInfo.itemId] = count;
			}
		}
	} else {
		// Large shop, it's better to get a cached map of all item counts and use it
		// We need a temporary map since the finished map should only contain items
		// available in the shop
		std::map<uint32_t, uint32_t> tempSaleMap;
		player->getAllItemTypeCount(tempSaleMap);

		// We must still check manually for the special items that require subtype matches
		// (That is, fluids such as potions etc., actually these items are very few since
		// health potions now use their own ID)
		for (const ShopInfo& shopInfo : shop) {
			if (shopInfo.sellPrice == 0) {
				continue;
			}

			int8_t subtype = -1;

			const ItemType& itemType = Item::items[shopInfo.itemId];
			if (itemType.hasSubType() && !itemType.stackable) {
				subtype = (shopInfo.subType == 0 ? -1 : shopInfo.subType);
			}

			if (subtype != -1) {
				uint32_t count;
				if (!itemType.isFluidContainer() && !itemType.isSplash()) {
					count = player->getItemTypeCount(shopInfo.itemId, subtype); // This shop item requires extra checks
				} else {
					count = subtype;
				}

				if (count > 0) {
					saleMap[shopInfo.itemId] = count;
				}
			} else {
				std::map<uint32_t, uint32_t>::const_iterator findIt = tempSaleMap.find(shopInfo.itemId);
				if (findIt != tempSaleMap.end() && findIt->second > 0) {
					saleMap[shopInfo.itemId] = findIt->second;
				}
			}
		}
	}

	uint8_t itemsToSend = std::min<size_t>(saleMap.size(), std::numeric_limits<uint8_t>::max());
	msg.addByte(itemsToSend);

	uint8_t i = 0;
	for (std::map<uint16_t, uint32_t>::const_iterator it = saleMap.begin(); i < itemsToSend; ++it, ++i) {
		msg.addItemId(it->first);
		msg.addByte(std::min<uint32_t>(it->second, std::numeric_limits<uint8_t>::max()));
	}

	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendMarketEnter(uint32_t depotId)
{
	NetworkMessage msg;
	msg.addByte(0xF6);

	msg.add<uint64_t>(player->getBankBalance());
	msg.addByte(std::min<uint32_t>(IOMarket::getPlayerOfferCount(player->getGUID()), std::numeric_limits<uint8_t>::max()));

	DepotChest* depotChest = player->getDepotChest(depotId, false);
	if (!depotChest) {
		msg.add<uint16_t>(0x00);
		writeToOutputBuffer(msg);
		return;
	}

	player->setInMarket(true);

	std::map<uint16_t, uint32_t> depotItems;
	std::forward_list<Container*> containerList { depotChest };

	do {
		Container* container = containerList.front();
		containerList.pop_front();

		for (Item* item : container->getItemList()) {
			Container* c = item->getContainer();
			if (c && !c->empty()) {
				containerList.push_front(c);
				continue;
			}

			const ItemType& itemType = Item::items[item->getID()];
			if (itemType.wareId == 0) {
				continue;
			}

			if (c && (!itemType.isContainer() || c->capacity() != itemType.maxItems)) {
				continue;
			}

			if (!item->hasMarketAttributes()) {
				continue;
			}

			depotItems[itemType.wareId] += Item::countByType(item, -1);
		}
	} while (!containerList.empty());

	uint16_t itemsToSend = std::min<size_t>(depotItems.size(), std::numeric_limits<uint16_t>::max());
	msg.add<uint16_t>(itemsToSend);

	uint16_t i = 0;
	for (std::map<uint16_t, uint32_t>::const_iterator it = depotItems.begin(); i < itemsToSend; ++it, ++i) {
		msg.add<uint16_t>(it->first);
		msg.add<uint16_t>(std::min<uint32_t>(0xFFFF, it->second));
	}

	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendMarketLeave()
{
	NetworkMessage msg;
	msg.addByte(0xF7);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendMarketBrowseItem(uint16_t itemId, const MarketOfferList& buyOffers, const MarketOfferList& sellOffers)
{
	NetworkMessage msg;

	msg.addByte(0xF9);
	msg.addItemId(itemId);

	msg.add<uint32_t>(buyOffers.size());
	for (const MarketOffer& offer : buyOffers) {
		msg.add<uint32_t>(offer.timestamp);
		msg.add<uint16_t>(offer.counter);
		msg.add<uint16_t>(offer.amount);
		msg.add<uint32_t>(offer.price);
		msg.addString(offer.playerName);
	}

	msg.add<uint32_t>(sellOffers.size());
	for (const MarketOffer& offer : sellOffers) {
		msg.add<uint32_t>(offer.timestamp);
		msg.add<uint16_t>(offer.counter);
		msg.add<uint16_t>(offer.amount);
		msg.add<uint32_t>(offer.price);
		msg.addString(offer.playerName);
	}

	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendMarketAcceptOffer(const MarketOfferEx& offer)
{
	NetworkMessage msg;
	msg.addByte(0xF9);
	msg.addItemId(offer.itemId);

	if (offer.type == MARKETACTION_BUY) {
		msg.add<uint32_t>(0x01);
		msg.add<uint32_t>(offer.timestamp);
		msg.add<uint16_t>(offer.counter);
		msg.add<uint16_t>(offer.amount);
		msg.add<uint32_t>(offer.price);
		msg.addString(offer.playerName);
		msg.add<uint32_t>(0x00);
	} else {
		msg.add<uint32_t>(0x00);
		msg.add<uint32_t>(0x01);
		msg.add<uint32_t>(offer.timestamp);
		msg.add<uint16_t>(offer.counter);
		msg.add<uint16_t>(offer.amount);
		msg.add<uint32_t>(offer.price);
		msg.addString(offer.playerName);
	}

	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendMarketBrowseOwnOffers(const MarketOfferList& buyOffers, const MarketOfferList& sellOffers)
{
	NetworkMessage msg;
	msg.addByte(0xF9);
	msg.add<uint16_t>(MARKETREQUEST_OWN_OFFERS);

	msg.add<uint32_t>(buyOffers.size());
	for (const MarketOffer& offer : buyOffers) {
		msg.add<uint32_t>(offer.timestamp);
		msg.add<uint16_t>(offer.counter);
		msg.addItemId(offer.itemId);
		msg.add<uint16_t>(offer.amount);
		msg.add<uint32_t>(offer.price);
	}

	msg.add<uint32_t>(sellOffers.size());
	for (const MarketOffer& offer : sellOffers) {
		msg.add<uint32_t>(offer.timestamp);
		msg.add<uint16_t>(offer.counter);
		msg.addItemId(offer.itemId);
		msg.add<uint16_t>(offer.amount);
		msg.add<uint32_t>(offer.price);
	}

	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendMarketCancelOffer(const MarketOfferEx& offer)
{
	NetworkMessage msg;
	msg.addByte(0xF9);
	msg.add<uint16_t>(MARKETREQUEST_OWN_OFFERS);

	if (offer.type == MARKETACTION_BUY) {
		msg.add<uint32_t>(0x01);
		msg.add<uint32_t>(offer.timestamp);
		msg.add<uint16_t>(offer.counter);
		msg.addItemId(offer.itemId);
		msg.add<uint16_t>(offer.amount);
		msg.add<uint32_t>(offer.price);
		msg.add<uint32_t>(0x00);
	} else {
		msg.add<uint32_t>(0x00);
		msg.add<uint32_t>(0x01);
		msg.add<uint32_t>(offer.timestamp);
		msg.add<uint16_t>(offer.counter);
		msg.addItemId(offer.itemId);
		msg.add<uint16_t>(offer.amount);
		msg.add<uint32_t>(offer.price);
	}

	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendMarketBrowseOwnHistory(const HistoryMarketOfferList& buyOffers, const HistoryMarketOfferList& sellOffers)
{
	uint32_t i = 0;
	std::map<uint32_t, uint16_t> counterMap;
	uint32_t buyOffersToSend = std::min<uint32_t>(buyOffers.size(), 810 + std::max<int32_t>(0, 810 - sellOffers.size()));
	uint32_t sellOffersToSend = std::min<uint32_t>(sellOffers.size(), 810 + std::max<int32_t>(0, 810 - buyOffers.size()));

	NetworkMessage msg;
	msg.addByte(0xF9);
	msg.add<uint16_t>(MARKETREQUEST_OWN_HISTORY);

	msg.add<uint32_t>(buyOffersToSend);
	for (auto it = buyOffers.begin(); i < buyOffersToSend; ++it, ++i) {
		msg.add<uint32_t>(it->timestamp);
		msg.add<uint16_t>(counterMap[it->timestamp]++);
		msg.addItemId(it->itemId);
		msg.add<uint16_t>(it->amount);
		msg.add<uint32_t>(it->price);
		msg.addByte(it->state);
	}

	counterMap.clear();
	i = 0;

	msg.add<uint32_t>(sellOffersToSend);
	for (auto it = sellOffers.begin(); i < sellOffersToSend; ++it, ++i) {
		msg.add<uint32_t>(it->timestamp);
		msg.add<uint16_t>(counterMap[it->timestamp]++);
		msg.addItemId(it->itemId);
		msg.add<uint16_t>(it->amount);
		msg.add<uint32_t>(it->price);
		msg.addByte(it->state);
	}

	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendMarketDetail(uint16_t itemId)
{
	NetworkMessage msg;
	msg.addByte(0xF8);
	msg.addItemId(itemId);

	const ItemType& it = Item::items[itemId];
	if (it.armor != 0) {
		msg.addString(std::to_string(it.armor));
	} else {
		msg.add<uint16_t>(0x00);
	}

	if (it.attack != 0) {
		// TODO: chance to hit, range
		// example:
		// "attack +x, chance to hit +y%, z fields"
		if (it.abilities && it.abilities->elementType != COMBAT_NONE && it.abilities->elementDamage != 0) {
			std::ostringstream ss;
			ss << it.attack << " physical +" << it.abilities->elementDamage << ' ' << getCombatName(it.abilities->elementType);
			msg.addString(ss.str());
		} else {
			msg.addString(std::to_string(it.attack));
		}
	} else {
		msg.add<uint16_t>(0x00);
	}

	if (it.isContainer()) {
		msg.addString(std::to_string(it.maxItems));
	} else {
		msg.add<uint16_t>(0x00);
	}

	if (it.defense != 0) {
		if (it.extraDefense != 0) {
			std::ostringstream ss;
			ss << it.defense << ' ' << std::showpos << it.extraDefense << std::noshowpos;
			msg.addString(ss.str());
		} else {
			msg.addString(std::to_string(it.defense));
		}
	} else {
		msg.add<uint16_t>(0x00);
	}

	if (!it.description.empty()) {
		const std::string& descr = it.description;
		if (descr.back() == '.') {
			msg.addString(std::string(descr, 0, descr.length() - 1));
		} else {
			msg.addString(descr);
		}
	} else {
		msg.add<uint16_t>(0x00);
	}

	if (it.decayTime != 0) {
		std::ostringstream ss;
		ss << it.decayTime << " seconds";
		msg.addString(ss.str());
	} else {
		msg.add<uint16_t>(0x00);
	}

	if (it.abilities) {
		std::ostringstream ss;
		bool separator = false;

		for (size_t i = 0; i < COMBAT_COUNT; ++i) {
			if (it.abilities->absorbPercent[i] == 0) {
				continue;
			}

			if (separator) {
				ss << ", ";
			} else {
				separator = true;
			}

			ss << getCombatName(indexToCombatType(i)) << ' ' << std::showpos << it.abilities->absorbPercent[i] << std::noshowpos << '%';
		}

		msg.addString(ss.str());
	} else {
		msg.add<uint16_t>(0x00);
	}

	if (it.minReqLevel != 0) {
		msg.addString(std::to_string(it.minReqLevel));
	} else {
		msg.add<uint16_t>(0x00);
	}

	if (it.minReqMagicLevel != 0) {
		msg.addString(std::to_string(it.minReqMagicLevel));
	} else {
		msg.add<uint16_t>(0x00);
	}

	msg.addString(it.vocationString);

	msg.addString(it.runeSpellName);

	if (it.abilities) {
		std::ostringstream ss;
		bool separator = false;

		for (uint8_t i = SKILL_FIRST; i <= SKILL_LAST; i++) {
			if (!it.abilities->skills[i]) {
				continue;
			}

			if (separator) {
				ss << ", ";
			} else {
				separator = true;
			}

			ss << getSkillName(i) << ' ' << std::showpos << it.abilities->skills[i] << std::noshowpos;
		}

		if (it.abilities->stats[STAT_MAGICPOINTS] != 0) {
			if (separator) {
				ss << ", ";
			} else {
				separator = true;
			}

			ss << "magic level " << std::showpos << it.abilities->stats[STAT_MAGICPOINTS] << std::noshowpos;
		}

		if (it.abilities->speed != 0) {
			if (separator) {
				ss << ", ";
			}

			ss << "speed " << std::showpos << (it.abilities->speed >> 1) << std::noshowpos;
		}

		msg.addString(ss.str());
	} else {
		msg.add<uint16_t>(0x00);
	}

	if (it.charges != 0) {
		msg.addString(std::to_string(it.charges));
	} else {
		msg.add<uint16_t>(0x00);
	}

	std::string weaponName = getWeaponName(it.weaponType);

	if (it.slotPosition & SLOTP_TWO_HAND) {
		if (!weaponName.empty()) {
			weaponName += ", two-handed";
		} else {
			weaponName = "two-handed";
		}
	}

	msg.addString(weaponName);

	if (it.weight != 0) {
		std::ostringstream ss;
		if (it.weight < 10) {
			ss << "0.0" << it.weight;
		} else if (it.weight < 100) {
			ss << "0." << it.weight;
		} else {
			std::string weightString = std::to_string(it.weight);
			weightString.insert(weightString.end() - 2, '.');
			ss << weightString;
		}
		ss << " oz";
		msg.addString(ss.str());
	} else {
		msg.add<uint16_t>(0x00);
	}

	MarketStatistics* statistics = IOMarket::getInstance().getPurchaseStatistics(itemId);
	if (statistics) {
		msg.addByte(0x01);
		msg.add<uint32_t>(statistics->numTransactions);
		msg.add<uint32_t>(std::min<uint64_t>(std::numeric_limits<uint32_t>::max(), statistics->totalPrice));
		msg.add<uint32_t>(statistics->highestPrice);
		msg.add<uint32_t>(statistics->lowestPrice);
	} else {
		msg.addByte(0x00);
	}

	statistics = IOMarket::getInstance().getSaleStatistics(itemId);
	if (statistics) {
		msg.addByte(0x01);
		msg.add<uint32_t>(statistics->numTransactions);
		msg.add<uint32_t>(std::min<uint64_t>(std::numeric_limits<uint32_t>::max(), statistics->totalPrice));
		msg.add<uint32_t>(statistics->highestPrice);
		msg.add<uint32_t>(statistics->lowestPrice);
	} else {
		msg.addByte(0x00);
	}

	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendQuestLog()
{
	NetworkMessage msg;
	msg.addByte(0xF0);
	msg.add<uint16_t>(g_game.quests.getQuestsCount(player));

	for (const Quest& quest : g_game.quests.getQuests()) {
		if (quest.isStarted(player)) {
			msg.add<uint16_t>(quest.getID());
			msg.addString(quest.getName());
			msg.addByte(quest.isCompleted(player));
		}
	}

	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendQuestLine(const Quest* quest)
{
	NetworkMessage msg;
	msg.addByte(0xF1);
	msg.add<uint16_t>(quest->getID());
	msg.addByte(quest->getMissionsCount(player));

	for (const Mission& mission : quest->getMissions()) {
		if (mission.isStarted(player)) {
			msg.addString(mission.getName(player));
			msg.addString(mission.getDescription(player));
		}
	}

	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendTradeItemRequest(const std::string& traderName, const Item* item, bool ack)
{
	NetworkMessage msg;

	if (ack) {
		msg.addByte(0x7D);
	} else {
		msg.addByte(0x7E);
	}

	msg.addString(traderName);

	if (const Container* tradeContainer = item->getContainer()) {
		std::list<const Container*> listContainer {tradeContainer};
		std::list<const Item*> itemList {tradeContainer};
		while (!listContainer.empty()) {
			const Container* container = listContainer.front();
			listContainer.pop_front();

			for (Item* containerItem : container->getItemList()) {
				Container* tmpContainer = containerItem->getContainer();
				if (tmpContainer) {
					listContainer.push_back(tmpContainer);
				}
				itemList.push_back(containerItem);
			}
		}

		msg.addByte(itemList.size());
		for (const Item* listItem : itemList) {
			msg.addItem(listItem);
		}
	} else {
		msg.addByte(0x01);
		msg.addItem(item);
	}
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendCloseTrade()
{
	NetworkMessage msg;
	msg.addByte(0x7F);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendCloseContainer(uint8_t cid)
{
	NetworkMessage msg;
	msg.addByte(0x6F);
	msg.addByte(cid);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendCreatureTurn(const Creature* creature, uint32_t stackPos)
{
	if (!canSee(creature)) {
		return;
	}

	NetworkMessage msg;
	msg.addByte(0x6B);
	msg.addPosition(creature->getPosition());
	msg.addByte(stackPos);
	msg.add<uint16_t>(0x63);
	msg.add<uint32_t>(creature->getID());
	msg.addByte(creature->getDirection());
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendCreatureSay(const Creature* creature, SpeakClasses type, const std::string& text, const Position* pos/* = nullptr*/)
{
	NetworkMessage msg;
	msg.addByte(0xAA);

	static uint32_t statementId = 0;
	msg.add<uint32_t>(++statementId);

	msg.addString(creature->getName());

	//Add level only for players
	if (const Player* speaker = creature->getPlayer()) {
		msg.add<uint16_t>(speaker->getLevel());
	} else {
		msg.add<uint16_t>(0x00);
	}

	msg.addByte(type);
	if (pos) {
		msg.addPosition(*pos);
	} else {
		msg.addPosition(creature->getPosition());
	}

	msg.addString(text);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendToChannel(const Creature* creature, SpeakClasses type, const std::string& text, uint16_t channelId)
{
	NetworkMessage msg;
	msg.addByte(0xAA);

	static uint32_t statementId = 0;
	msg.add<uint32_t>(++statementId);
	if (!creature) {
		msg.add<uint32_t>(0x00);
	} else if (type == TALKTYPE_CHANNEL_R2) {
		msg.add<uint32_t>(0x00);
		type = TALKTYPE_CHANNEL_R1;
	} else {
		msg.addString(creature->getName());
		//Add level only for players
		if (const Player* speaker = creature->getPlayer()) {
			msg.add<uint16_t>(speaker->getLevel());
		} else {
			msg.add<uint16_t>(0x00);
		}
	}

	msg.addByte(type);
	msg.add<uint16_t>(channelId);
	msg.addString(text);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendPrivateMessage(const Player* speaker, SpeakClasses type, const std::string& text)
{
	NetworkMessage msg;
	msg.addByte(0xAA);
	static uint32_t statementId = 0;
	msg.add<uint32_t>(++statementId);
	if (speaker) {
		msg.addString(speaker->getName());
		msg.add<uint16_t>(speaker->getLevel());
	} else {
		msg.add<uint32_t>(0x00);
	}
	msg.addByte(type);
	msg.addString(text);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendCancelTarget()
{
	NetworkMessage msg;
	msg.addByte(0xA3);
	msg.add<uint32_t>(0x00);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendChangeSpeed(const Creature* creature, uint32_t speed)
{
	NetworkMessage msg;
	msg.addByte(0x8F);
	msg.add<uint32_t>(creature->getID());
	msg.add<uint16_t>(creature->getBaseSpeed() / 2);
	msg.add<uint16_t>(speed / 2);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendCancelWalk()
{
	NetworkMessage msg;
	msg.addByte(0xB5);
	msg.addByte(player->getDirection());
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendSkills()
{
	NetworkMessage msg;
	AddPlayerSkills(msg);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendPing()
{
	NetworkMessage msg;
	msg.addByte(0x1D);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendPingBack()
{
	NetworkMessage msg;
	msg.addByte(0x1E);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendDistanceShoot(const Position& from, const Position& to, uint8_t type)
{
	NetworkMessage msg;
	msg.addByte(0x85);
	msg.addPosition(from);
	msg.addPosition(to);
	msg.addByte(type);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendMagicEffect(const Position& pos, uint8_t type)
{
	if (!canSee(pos)) {
		return;
	}

	NetworkMessage msg;
	msg.addByte(0x83);
	msg.addPosition(pos);
	msg.addByte(type);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendCreatureHealth(const Creature* creature)
{
	NetworkMessage msg;
	msg.addByte(0x8C);
	msg.add<uint32_t>(creature->getID());

	if (creature->isHealthHidden()) {
		msg.addByte(0x00);
	} else {
		msg.addByte(std::ceil((static_cast<double>(creature->getHealth()) / std::max<int32_t>(creature->getMaxHealth(), 1)) * 100));
	}
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendFYIBox(const std::string& message)
{
	NetworkMessage msg;
	msg.addByte(0x15);
	msg.addString(message);
	writeToOutputBuffer(msg);
}

//tile
void ProtocolGameBase::sendMapDescription(const Position& pos)
{
	if (otclientV8) {
		int32_t startz, endz, zstep;

		if (pos.z > 7) {
			startz = pos.z - 2;
			endz = std::min<int32_t>(MAP_MAX_LAYERS - 1, pos.z + 2);
			zstep = 1;
		}
		else {
			startz = 7;
			endz = 0;
			zstep = -1;
		}

		for (int32_t nz = startz; nz != endz + zstep; nz += zstep) {
			sendFloorDescription(pos, nz);
		}
	}
	else {
		NetworkMessage msg;
		msg.addByte(0x64);
		msg.addPosition(player->getPosition());
		GetMapDescription(pos.x - awareRange.left(), pos.y - awareRange.top(), pos.z, awareRange.horizontal(), awareRange.vertical(), msg);
		writeToOutputBuffer(msg);
	}
}

void ProtocolGameBase::sendFloorDescription(const Position& pos, int floor)
{
	// When map view range is big, let's say 30x20 all floors may not fit in single packets
	// So we split one packet with every floor to few packets with single floor
	NetworkMessage msg;
	msg.addByte(0x4B);
	msg.addPosition(player->getPosition());
	msg.addByte(floor);
	int32_t skip = -1;
	GetFloorDescription(msg, pos.x - awareRange.left(), pos.y - awareRange.top(), floor, awareRange.horizontal(), awareRange.vertical(), pos.z - floor, skip);
	if (skip >= 0) {
		msg.addByte(skip);
		msg.addByte(0xFF);
	}
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendAddTileItem(const Position& pos, const Item* item)
{
	if (!canSee(pos)) {
		return;
	}

	NetworkMessage msg;
	msg.addByte(0x6A);
	msg.addPosition(pos);
	msg.addItem(item);
	writeToOutputBuffer(msg);

	checkPredictiveWalking(pos);
}

void ProtocolGameBase::sendUpdateTileItem(const Position& pos, uint32_t stackpos, const Item* item)
{
	if (!canSee(pos)) {
		return;
	}

	NetworkMessage msg;
	msg.addByte(0x6B);
	msg.addPosition(pos);
	msg.addByte(stackpos);
	msg.addItem(item);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendRemoveTileThing(const Position& pos, uint32_t stackpos)
{
	if (!canSee(pos)) {
		return;
	}

	NetworkMessage msg;
	RemoveTileThing(msg, pos, stackpos);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendUpdateTile(const Tile* tile, const Position& pos)
{
	if (!canSee(pos)) {
		return;
	}

	NetworkMessage msg;
	msg.addByte(0x69);
	msg.addPosition(pos);

	if (tile) {
		GetTileDescription(tile, msg);
		msg.addByte(0x00);
		msg.addByte(0xFF);
	} else {
		msg.addByte(0x01);
		msg.addByte(0xFF);
	}

	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendPendingStateEntered()
{
	NetworkMessage msg;
	msg.addByte(0x0A);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendEnterWorld()
{
	NetworkMessage msg;
	msg.addByte(0x0F);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendFightModes()
{
	NetworkMessage msg;
	msg.addByte(0xA7);
	msg.addByte(player->fightMode);
	msg.addByte(player->chaseMode);
	msg.addByte(player->secureMode);
	msg.addByte(PVP_MODE_DOVE);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendAddCreature(const Creature* creature, const Position& pos, int32_t stackpos, bool isLogin)
{
	if (!canSee(pos)) {
		return;
	}

	if (creature != player) {
		if (stackpos != -1) {
			NetworkMessage msg;
			msg.addByte(0x6A);
			msg.addPosition(pos);
			msg.addByte(stackpos);

			bool known;
			uint32_t removedKnown;
			checkCreatureAsKnown(creature->getID(), known, removedKnown);
			AddCreature(msg, creature, known, removedKnown);
			writeToOutputBuffer(msg);
		}

		if (isLogin) {
			sendMagicEffect(pos, CONST_ME_TELEPORT);
		}
		return;
	}

	NetworkMessage msg;
	msg.addByte(0x17);

	msg.add<uint32_t>(player->getID());
	msg.add<uint16_t>(0x32); // beat duration (50)


	// can report bugs?
	if (player->getAccountType() >= ACCOUNT_TYPE_TUTOR) {
		msg.addByte(0x01);
	} else {
		msg.addByte(0x00);
	}

	msg.addByte(0x00); // can change pvp framing option
	msg.addByte(0x00); // expert mode button enabled

	msg.add<uint16_t>(0x00); // URL (string) to ingame store images
	msg.add<uint16_t>(25); // premium coin package size

	writeToOutputBuffer(msg);

	sendPendingStateEntered();
	sendEnterWorld();
	sendMapDescription(pos);

	if (isLogin) {
		sendMagicEffect(pos, CONST_ME_TELEPORT);
	}

	sendInventoryItem(CONST_SLOT_HEAD, player->getInventoryItem(CONST_SLOT_HEAD));
	sendInventoryItem(CONST_SLOT_NECKLACE, player->getInventoryItem(CONST_SLOT_NECKLACE));
	sendInventoryItem(CONST_SLOT_BACKPACK, player->getInventoryItem(CONST_SLOT_BACKPACK));
	sendInventoryItem(CONST_SLOT_ARMOR, player->getInventoryItem(CONST_SLOT_ARMOR));
	sendInventoryItem(CONST_SLOT_RIGHT, player->getInventoryItem(CONST_SLOT_RIGHT));
	sendInventoryItem(CONST_SLOT_LEFT, player->getInventoryItem(CONST_SLOT_LEFT));
	sendInventoryItem(CONST_SLOT_LEGS, player->getInventoryItem(CONST_SLOT_LEGS));
	sendInventoryItem(CONST_SLOT_FEET, player->getInventoryItem(CONST_SLOT_FEET));
	sendInventoryItem(CONST_SLOT_RING, player->getInventoryItem(CONST_SLOT_RING));
	sendInventoryItem(CONST_SLOT_AMMO, player->getInventoryItem(CONST_SLOT_AMMO));

	sendStats();
	sendSkills();

	//gameworld light-settings
	sendWorldLight(g_game.getWorldLightInfo());

	//player light level
	sendCreatureLight(creature);

	sendVIPEntries();

	sendBasicData();
	player->sendIcons();
}

void ProtocolGameBase::sendMoveCreature(const Creature* creature, const Position& newPos, int32_t newStackPos, const Position& oldPos, int32_t oldStackPos, bool teleport)
{
	if (creature == player) {
		if (oldStackPos >= 10) {
			sendMapDescription(newPos);
		} else if (teleport) {
			NetworkMessage msg;
			RemoveTileThing(msg, oldPos, oldStackPos);
			writeToOutputBuffer(msg);
			sendMapDescription(newPos);
		} else {
			NetworkMessage msg;
			if (oldPos.z == 7 && newPos.z >= 8) {
				RemoveTileThing(msg, oldPos, oldStackPos);
			} else {
				msg.addByte(0x6D);
				msg.addPosition(oldPos);
				msg.addByte(oldStackPos);
				msg.addPosition(newPos);
			}

			if (newPos.z > oldPos.z) {
				MoveDownCreature(msg, creature, newPos, oldPos);
			} else if (newPos.z < oldPos.z) {
				MoveUpCreature(msg, creature, newPos, oldPos);
			}

			if (oldPos.y > newPos.y) { // north, for old x
				msg.addByte(0x65);
				GetMapDescription(oldPos.x - 8, newPos.y - 6, newPos.z, 18, 1, msg);
			} else if (oldPos.y < newPos.y) { // south, for old x
				msg.addByte(0x67);
				GetMapDescription(oldPos.x - 8, newPos.y + 7, newPos.z, 18, 1, msg);
			}

			if (oldPos.x < newPos.x) { // east, [with new y]
				msg.addByte(0x66);
				GetMapDescription(newPos.x + 9, newPos.y - 6, newPos.z, 1, 14, msg);
			} else if (oldPos.x > newPos.x) { // west, [with new y]
				msg.addByte(0x68);
				GetMapDescription(newPos.x - 8, newPos.y - 6, newPos.z, 1, 14, msg);
			}
			writeToOutputBuffer(msg);
		}
	} else if (canSee(oldPos) && canSee(creature->getPosition())) {
		if (teleport || (oldPos.z == 7 && newPos.z >= 8) || oldStackPos >= 10) {
			sendRemoveTileThing(oldPos, oldStackPos);
			sendAddCreature(creature, newPos, newStackPos, false);
		} else {
			NetworkMessage msg;
			msg.addByte(0x6D);
			msg.addPosition(oldPos);
			msg.addByte(oldStackPos);
			msg.addPosition(creature->getPosition());
			writeToOutputBuffer(msg);
		}
	} else if (canSee(oldPos)) {
		sendRemoveTileThing(oldPos, oldStackPos);
	} else if (canSee(creature->getPosition())) {
		sendAddCreature(creature, newPos, newStackPos, false);
	}
}

void ProtocolGameBase::sendInventoryItem(slots_t slot, const Item* item)
{
	NetworkMessage msg;
	if (item) {
		msg.addByte(0x78);
		msg.addByte(slot);
		msg.addItem(item);
	} else {
		msg.addByte(0x79);
		msg.addByte(slot);
	}
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendAddContainerItem(uint8_t cid, uint16_t slot, const Item* item)
{
	NetworkMessage msg;
	msg.addByte(0x70);
	msg.addByte(cid);
	msg.add<uint16_t>(slot);
	msg.addItem(item);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendUpdateContainerItem(uint8_t cid, uint16_t slot, const Item* item)
{
	NetworkMessage msg;
	msg.addByte(0x71);
	msg.addByte(cid);
	msg.add<uint16_t>(slot);
	msg.addItem(item);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendRemoveContainerItem(uint8_t cid, uint16_t slot, const Item* lastItem)
{
	NetworkMessage msg;
	msg.addByte(0x72);
	msg.addByte(cid);
	msg.add<uint16_t>(slot);
	if (lastItem) {
		msg.addItem(lastItem);
	}
	else {
		msg.add<uint16_t>(0x00);
	}
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendTextWindow(uint32_t windowTextId, Item* item, uint16_t maxlen, bool canWrite)
{
	NetworkMessage msg;
	msg.addByte(0x96);
	msg.add<uint32_t>(windowTextId);
	msg.addItem(item);

	if (canWrite) {
		msg.add<uint16_t>(maxlen);
		msg.addString(item->getText());
	} else {
		const std::string& text = item->getText();
		msg.add<uint16_t>(text.size());
		msg.addString(text);
	}

	const std::string& writer = item->getWriter();
	if (!writer.empty()) {
		msg.addString(writer);
	} else {
		msg.add<uint16_t>(0x00);
	}

	time_t writtenDate = item->getDate();
	if (writtenDate != 0) {
		msg.addString(formatDateShort(writtenDate));
	} else {
		msg.add<uint16_t>(0x00);
	}

	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendTextWindow(uint32_t windowTextId, uint32_t itemId, const std::string& text)
{
	NetworkMessage msg;
	msg.addByte(0x96);
	msg.add<uint32_t>(windowTextId);
	msg.addItem(itemId, 1);
	msg.add<uint16_t>(text.size());
	msg.addString(text);
	msg.add<uint16_t>(0x00);
	msg.add<uint16_t>(0x00);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendHouseWindow(uint32_t windowTextId, const std::string& text)
{
	NetworkMessage msg;
	msg.addByte(0x97);
	msg.addByte(0x00);
	msg.add<uint32_t>(windowTextId);
	msg.addString(text);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendOutfitWindow()
{
	NetworkMessage msg;
	msg.addByte(0xC8);

	Outfit_t currentOutfit = player->getDefaultOutfit();
	AddOutfit(msg, currentOutfit);

	switch (player->getSex()) {
	case PLAYERSEX_FEMALE: {
		msg.add<uint16_t>(136);
		if (player->isPremium()) {
			msg.add<uint16_t>(142);
		}
		else {
			msg.add<uint16_t>(139);
		}

		break;
	}

	case PLAYERSEX_MALE: {
		msg.add<uint16_t>(128);
		if (player->isPremium()) {
			msg.add<uint16_t>(134);
		}
		else {
			msg.add<uint16_t>(131);
		}

		break;
	}

	default: {
		msg.add<uint16_t>(128);
		msg.add<uint16_t>(134);
	}
	}

	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendUpdatedVIPStatus(uint32_t guid, VipStatus_t newStatus)
{
	NetworkMessage msg;
	msg.addByte(newStatus ? 0xD3 : 0xD4);
	msg.add<uint32_t>(guid);
	msg.addByte(newStatus);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendVIP(uint32_t guid, const std::string& name, VipStatus_t status)
{
	NetworkMessage msg;
	msg.addByte(0xD2);
	msg.add<uint32_t>(guid);
	msg.addString(name);
	msg.addByte(status);
	writeToOutputBuffer(msg);
}


void ProtocolGameBase::sendVIPEntries()
{
	const std::forward_list<VIPEntry>& vipEntries = IOLoginData::getVIPEntries(player->getAccount());

	for (const VIPEntry& entry : vipEntries) {
		VipStatus_t vipStatus = VIPSTATUS_ONLINE;

		Player* vipPlayer = g_game.getPlayerByGUID(entry.guid);

		if (!vipPlayer || vipPlayer->isInGhostMode() || player->isAccessPlayer()) {
			vipStatus = VIPSTATUS_OFFLINE;
		}

		sendVIP(entry.guid, entry.name, vipStatus);
	}
}

void ProtocolGameBase::sendModalWindow(const ModalWindow& modalWindow)
{
	NetworkMessage msg;
	msg.addByte(0xFA);

	msg.add<uint32_t>(modalWindow.id);
	msg.addString(modalWindow.title);
	msg.addString(modalWindow.message);

	msg.addByte(modalWindow.buttons.size());
	for (const auto& it : modalWindow.buttons) {
		msg.addString(it.first);
		msg.addByte(it.second);
	}

	msg.addByte(modalWindow.choices.size());
	for (const auto& it : modalWindow.choices) {
		msg.addString(it.first);
		msg.addByte(it.second);
	}

	msg.addByte(modalWindow.defaultEscapeButton);
	msg.addByte(modalWindow.defaultEnterButton);
	msg.addByte(modalWindow.priority ? 0x01 : 0x00);

	writeToOutputBuffer(msg);
}

////////////// Add common messages
void ProtocolGameBase::AddCreature(NetworkMessage& msg, const Creature* creature, bool known, uint32_t remove)
{

	const Player* otherPlayer = creature->getPlayer();

	if (known) {
		msg.add<uint16_t>(0x62);
		msg.add<uint32_t>(creature->getID());
	} else {
		msg.add<uint16_t>(0x61);
		msg.add<uint32_t>(remove);
		msg.add<uint32_t>(creature->getID());
		msg.addString(creature->getName());
	}

	if (creature->isHealthHidden()) {
		msg.addByte(0x00);
	} else {
		msg.addByte(std::ceil((static_cast<double>(creature->getHealth()) / std::max<int32_t>(creature->getMaxHealth(), 1)) * 100));
	}

	msg.addByte(creature->getDirection());

	if (!creature->isInGhostMode() && !creature->isInvisible()) {
		AddOutfit(msg, creature->getCurrentOutfit());
	} else {
		static Outfit_t outfit;
		AddOutfit(msg, outfit);
	}

	LightInfo lightInfo = creature->getCreatureLight();
	msg.addByte(player->isAccessPlayer() ? 0xFF : lightInfo.level);
	msg.addByte(lightInfo.color);

	msg.add<uint16_t>(creature->getStepSpeed() / 2);

	msg.addByte(player->getSkullClient(creature));
	msg.addByte(player->getPartyShield(otherPlayer));

	if (!known) {
		msg.addByte(player->getGuildEmblem(otherPlayer));
	}

	if (otherPlayer) {
		msg.add<uint16_t>(otherPlayer->getHelpers());
	} else {
		msg.add<uint16_t>(0x00);
	}

}

void ProtocolGameBase::AddPlayerStats(NetworkMessage& msg)
{
	msg.addByte(0xA0);

	msg.add<uint16_t>(std::min<int32_t>(player->getHealth(), std::numeric_limits<uint16_t>::max()));
	msg.add<uint16_t>(std::min<int32_t>(player->getMaxHealth(), std::numeric_limits<uint16_t>::max()));

	msg.add<uint16_t>(player->getFreeCapacity() / 100);

	msg.add<uint64_t>(player->getExperience());

	msg.add<uint16_t>(player->getLevel());
	msg.addByte(player->getLevelPercent());

	msg.add<uint16_t>(100); // base xp gain rate
	msg.add<uint16_t>(0); // xp voucher
	msg.add<uint16_t>(0); // low level bonus
	msg.add<uint16_t>(0); // xp boost
	msg.add<uint16_t>(100); // stamina multiplier (100 = x1.0)

	msg.add<uint16_t>(std::min<int32_t>(player->getMana(), std::numeric_limits<uint16_t>::max()));
	msg.add<uint16_t>(std::min<int32_t>(player->getMaxMana(), std::numeric_limits<uint16_t>::max()));

	msg.addByte(std::min<uint32_t>(player->getMagicLevel(), std::numeric_limits<uint8_t>::max()));
	msg.addByte(std::min<uint32_t>(player->getBaseMagicLevel(), std::numeric_limits<uint8_t>::max()));
	msg.addByte(player->getMagicLevelPercent());

	msg.addByte(player->getSoul());

	msg.add<uint16_t>(0); // xp boost time (seconds)
	msg.addByte(0); // enables exp boost in the store
}

void ProtocolGameBase::AddPlayerSkills(NetworkMessage& msg)
{
	msg.addByte(0xA1);

	for (uint8_t i = SKILL_FIRST; i <= SKILL_LAST; ++i) {
		msg.addByte(std::min<int32_t>(player->getSkillLevel(i), std::numeric_limits<uint16_t>::max()));
		msg.addByte(player->getSkillPercent(i));
	}
}

void ProtocolGameBase::AddOutfit(NetworkMessage& msg, const Outfit_t& outfit)
{
	msg.add<uint16_t>(outfit.lookType);

	if (outfit.lookType != 0) {
		msg.addByte(outfit.lookHead);
		msg.addByte(outfit.lookBody);
		msg.addByte(outfit.lookLegs);
		msg.addByte(outfit.lookFeet);
	} else {
		msg.addItemId(outfit.lookTypeEx);
	}
}

void ProtocolGameBase::AddCreatureLight(NetworkMessage& msg, const Creature* creature)
{
	LightInfo lightInfo = creature->getCreatureLight();

	msg.addByte(0x8D);
	msg.add<uint32_t>(creature->getID());
	msg.addByte((player->isAccessPlayer() ? 0xFF : lightInfo.level));
	msg.addByte(lightInfo.color);
}

//tile
void ProtocolGameBase::RemoveTileThing(NetworkMessage& msg, const Position& pos, uint32_t stackpos)
{
	if (stackpos >= 10) {
		return;
	}

	msg.addByte(0x6C);
	msg.addPosition(pos);
	msg.addByte(stackpos);
}

void ProtocolGameBase::MoveUpCreature(NetworkMessage& msg, const Creature* creature, const Position& newPos, const Position& oldPos)
{
	if (creature != player) {
		return;
	}

	//floor change up
	msg.addByte(0xBE);

	//going to surface
	if (newPos.z == 7) {
		int32_t skip = -1;
		GetFloorDescription(msg, oldPos.x - 8, oldPos.y - 6, 5, 18, 14, 3, skip); //(floor 7 and 6 already set)
		GetFloorDescription(msg, oldPos.x - 8, oldPos.y - 6, 4, 18, 14, 4, skip);
		GetFloorDescription(msg, oldPos.x - 8, oldPos.y - 6, 3, 18, 14, 5, skip);
		GetFloorDescription(msg, oldPos.x - 8, oldPos.y - 6, 2, 18, 14, 6, skip);
		GetFloorDescription(msg, oldPos.x - 8, oldPos.y - 6, 1, 18, 14, 7, skip);
		GetFloorDescription(msg, oldPos.x - 8, oldPos.y - 6, 0, 18, 14, 8, skip);

		if (skip >= 0) {
			msg.addByte(skip);
			msg.addByte(0xFF);
		}
	}
	//underground, going one floor up (still underground)
	else if (newPos.z > 7) {
		int32_t skip = -1;
		GetFloorDescription(msg, oldPos.x - 8, oldPos.y - 6, oldPos.getZ() - 3, 18, 14, 3, skip);

		if (skip >= 0) {
			msg.addByte(skip);
			msg.addByte(0xFF);
		}
	}

	//moving up a floor up makes us out of sync
	//west
	msg.addByte(0x68);
	GetMapDescription(oldPos.x - 8, oldPos.y - 5, newPos.z, 1, 14, msg);

	//north
	msg.addByte(0x65);
	GetMapDescription(oldPos.x - 8, oldPos.y - 6, newPos.z, 18, 1, msg);
}

void ProtocolGameBase::MoveDownCreature(NetworkMessage& msg, const Creature* creature, const Position& newPos, const Position& oldPos)
{
	if (creature != player) {
		return;
	}

	//floor change down
	msg.addByte(0xBF);

	//going from surface to underground
	if (newPos.z == 8) {
		int32_t skip = -1;

		GetFloorDescription(msg, oldPos.x - 8, oldPos.y - 6, newPos.z, 18, 14, -1, skip);
		GetFloorDescription(msg, oldPos.x - 8, oldPos.y - 6, newPos.z + 1, 18, 14, -2, skip);
		GetFloorDescription(msg, oldPos.x - 8, oldPos.y - 6, newPos.z + 2, 18, 14, -3, skip);

		if (skip >= 0) {
			msg.addByte(skip);
			msg.addByte(0xFF);
		}
	}
	//going further down
	else if (newPos.z > oldPos.z && newPos.z > 8 && newPos.z < 14) {
		int32_t skip = -1;
		GetFloorDescription(msg, oldPos.x - 8, oldPos.y - 6, newPos.z + 2, 18, 14, -3, skip);

		if (skip >= 0) {
			msg.addByte(skip);
			msg.addByte(0xFF);
		}
	}

	//moving down a floor makes us out of sync
	//east
	msg.addByte(0x66);
	GetMapDescription(oldPos.x + 9, oldPos.y - 7, newPos.z, 1, 14, msg);

	//south
	msg.addByte(0x67);
	GetMapDescription(oldPos.x - 8, oldPos.y + 7, newPos.z, 18, 1, msg);
}

void ProtocolGameBase::AddShopItem(NetworkMessage& msg, const ShopInfo& item)
{
	const ItemType& it = Item::items[item.itemId];
	msg.add<uint16_t>(it.clientId);

	if (it.isSplash() || it.isFluidContainer()) {
		msg.addByte(serverFluidToClient(item.subType));
	} else {
		msg.addByte(0x00);
	}

	msg.addString(item.realName);
	msg.add<uint32_t>(it.weight);
	msg.add<uint32_t>(item.buyPrice);
	msg.add<uint32_t>(item.sellPrice);
}


void ProtocolGameBase::parseExtendedOpcode(NetworkMessage& msg)
{
	uint8_t opcode = msg.getByte();
	const std::string& buffer = msg.getString();

	// process additional opcodes via lua script event
	addGameTask(&Game::parsePlayerExtendedOpcode, player->getID(), opcode, buffer);
}

// OTCv8
void ProtocolGameBase::sendFeatures()
{
	if (!otclientV8)
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

	if (features.empty())
		return;

	auto msg = getOutputBuffer(1024);
	msg->addByte(0x43);
	msg->add<uint16_t>(features.size());
	for (auto& feature : features) {
		msg->addByte((uint8_t)feature.first);
		msg->addByte(feature.second ? 1 : 0);
	}

	send(std::move(getCurrentBuffer())); // send this packet immediately
}

void ProtocolGameBase::parseChangeAwareRange(NetworkMessage& msg)
{
	uint8_t width = msg.get<uint8_t>();
	uint8_t height = msg.get<uint8_t>();

	g_dispatcher.addTask(createTask(std::bind(&ProtocolGameBase::updateAwareRange, getThis(), width, height)));
}

void ProtocolGameBase::updateAwareRange(int width, int height)
{
	if (!otclientV8)
		return;

	// If you want to change max awareRange, edit maxViewportX, maxViewportY, maxClientViewportX, maxClientViewportY in map.h
	awareRange.width = std::min(Map::maxViewportX * 2 - 1, std::min(Map::maxClientViewportX * 2 + 1, std::max(15, width)));
	awareRange.height = std::min(Map::maxViewportY * 2 - 1, std::min(Map::maxClientViewportY * 2 + 1, std::max(11, height)));
	// numbers must be odd
	if (awareRange.width % 2 != 1)
		awareRange.width -= 1;
	if (awareRange.height % 2 != 1)
		awareRange.height -= 1;

	sendAwareRange();
	sendMapDescription(player->getPosition()); // refresh map
}

void ProtocolGameBase::sendAwareRange()
{
	if (!otclientV8)
		return;

	NetworkMessage msg;
	msg.addByte(0x42);
	msg.add<uint8_t>(awareRange.width);
	msg.add<uint8_t>(awareRange.height);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::parseNewWalking(NetworkMessage& msg)
{
	uint32_t playerWalkId = msg.get<uint32_t>();
	int32_t predictiveWalkId = msg.get<int32_t>(); // extension for proxy system, currently not used
	Position playerPosition = msg.getPosition(); // local player position before moving, including prewalk
	uint8_t flags = msg.getByte(); // 0x01 - prewalk, 0x02 - autowalk

	uint16_t numdirs = msg.get<uint16_t>();
	if (numdirs == 0 || numdirs > 4096) {
		return;
	}

	std::list<Direction> path;
	for (uint16_t i = 0; i < numdirs; ++i) {
		uint8_t rawdir = msg.getByte();
		switch (rawdir) {
		case 1: path.push_back(DIRECTION_EAST); break;
		case 2: path.push_back(DIRECTION_NORTHEAST); break;
		case 3: path.push_back(DIRECTION_NORTH); break;
		case 4: path.push_back(DIRECTION_NORTHWEST); break;
		case 5: path.push_back(DIRECTION_WEST); break;
		case 6: path.push_back(DIRECTION_SOUTHWEST); break;
		case 7: path.push_back(DIRECTION_SOUTH); break;
		case 8: path.push_back(DIRECTION_SOUTHEAST); break;
		default: break;
		}
	}


	uint32_t playerId = player->getID();

	auto self(getThis());
	g_dispatcher.addTask(createTask([self, playerWalkId, predictiveWalkId, playerId, playerPosition, flags, path] {
		bool preWalk = flags & 0x01;
		Position destination = getNextPosition(*(path.begin()), playerPosition);
		if (preWalk && predictiveWalkId < self->walkMatrix.get(destination)) {
			self->walkId += 1;
			self->sendWalkId();
			return;
		}

		if (playerWalkId < self->walkId) {
			// this walk has been sent before player received previous newCancelWalk, so it's invalid, ignore it
			return;
		}

		g_game.playerNewWalk(playerId, playerPosition, flags, path);
		}));
}

void ProtocolGameBase::checkPredictiveWalking(const Position& pos)
{
	if (!otclientV8)
		return;

	if (walkMatrix.inRange(pos) && !g_game.map.canWalkTo(*player, pos)) {
		int newValue = walkMatrix.update(pos);
		sendPredictiveCancel(pos, newValue);
	}
}

void ProtocolGameBase::sendPredictiveCancel(const Position& pos, int value)
{
	if (!otclientV8)
		return;

	NetworkMessage msg;
	msg.addByte(0x46);
	msg.addPosition(pos);
	msg.addByte(player->getDirection());
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendWalkId()
{
	if (!otclientV8)
		return;

	NetworkMessage msg;
	msg.addByte(0x47);
	msg.add<uint32_t>(walkId);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendNewCancelWalk()
{
	if (!otclientV8)
		return;

	NetworkMessage msg;
	msg.addByte(0x45);
	msg.addByte(player->getDirection());
	writeToOutputBuffer(msg);
	walkId += 1;
	sendWalkId();
}

void ProtocolGameBase::parseNewPing(NetworkMessage& msg)
{
	uint32_t pingId = msg.get<uint32_t>();
	uint16_t localPing = msg.get<uint16_t>();
	uint16_t fps = msg.get<uint16_t>();

	addGameTask(&Game::playerReceiveNewPing, player->getID(), localPing, fps);
	g_dispatcher.addTask(createTask(std::bind(&ProtocolGameBase::sendNewPing, getThis(), pingId)));
}

void ProtocolGameBase::sendNewPing(uint32_t pingId)
{
	if (!otclientV8)
		return;

	NetworkMessage msg;
	msg.addByte(0x40);
	msg.add<uint32_t>(pingId);
	writeToOutputBuffer(msg);
}

void ProtocolGameBase::sendProgressbar(uint32_t id, uint32_t duration, bool ltr)
{
	if (!otclientV8 || otclientV8 < 260)
		return;

	NetworkMessage msg;
	msg.addByte(0x3b);
	msg.add<uint32_t>(id);
	msg.add<uint32_t>(duration);
	msg.addByte(ltr);
	writeToOutputBuffer(msg);
}
