/**
 *  ---------
 * |.##> <##.|  coolPACS
 * |#       #|  
 * |#       #|  Copyright (c) 2011-2014 CardContact Software & System Consulting
 * |'##> <##'|  Andreas Schwier, 32429 Minden, Germany (www.cardcontact.de)
 *  --------- 
 *
 *  This file is part of of the coolPACS project located at www.coolpacs.org
 *
 *  coolPACS is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  coolPACS is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with OpenSCDP; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * 
 * @fileoverview Simple Physical Access Control Terminal Simulation
 *
 * <p>This simulation shows the use of a SmartCard-HSM card for physical access control. The device authentication key and cv certificate
 *    is used to authenticate the card towards the reader and to establish a secure communication channel to read access control data.</p>
 * <p>If a PIN code is entered at the reader, then the code will be presented to the card using the secure communication channel, 
 *    thereby protecting the PIN code against eavesdropping at the air interface.
 *    As the verification response from the card is protected with a message authentication code, the terminal
 *    can proof that the verification was actually performed by the card.
 * <p>This demo requires at least the 3.7.1574 version of the Smart Card Shell.</p>
 */
 
load("../lib/smartcardhsm.js");

 
function AccessController(crdreader) {
	this.crdreader = crdreader;
	this.accessTerminal = new AccessTerminal();

	// Create a crypto object
	this.crypto = new Crypto();
}



AccessController.prototype.cardInserted = function(readername) {
	var card = new Card(readername);
    // print(card.reset(Card.RESET_COLD));
	this.check(card);
	card.close();
}



AccessController.prototype.cardRemoved = function() {
	this.accessTerminal.red();
}



AccessController.prototype.waitForCardInsertion = function() {
	this.card = null;

	do	{
		try	{
			this.card = new Card(this.crdreader);
//			card.reset(Card.RESET_COLD);
		}
		catch(e) {
//			print(e);
			this.card = null;
		}
	} while (this.card == null);
}



AccessController.prototype.waitForCardRemoval = function() {
	while (true) {
		try	{
			var card = new Card(this.crdreader);
			card.close();
		}
		catch(e) {
			return;
		}
	}
}



AccessController.prototype.checkAccessWithSCHSM = function(card) {
	var starttime = new Date();
	print("Started at " + starttime);

	try	{
		var ac = new SmartCardHSM(card);
	}
	catch(e) {
		print(e);
		return false;
	}
	
	// var rsp = ac.readBinary(SmartCardHSM.C_DevAut);
	
    var rsp = new ByteString("", HEX);
    var offset = 0;
    
    do {
        var data = card.sendApdu(0x00, 0xB1, 0x2F, 0x02, new ByteString("5402", HEX).concat(ByteString.valueOf(offset, 2)), 200, [0x9000, 0x6282]);
        rsp = rsp.concat(data);
        offset += data.length;
    } while (data.length > 0 && card.SW != 0x6282);
    
    var chain = SmartCardHSM.validateCertificateChain(this.crypto, rsp);

	try	{
		ac.openSecureChannel(this.crypto, chain.publicKey);
		var pin = this.accessTerminal.getPIN();
		if (pin.length > 0) {
			var sw = ac.verifyUserPIN(new ByteString(pin, ASCII));
			if (sw != 0x9000) {
				print("PIN wrong !!!");
				return false;
			}
		}
	}
	catch(e) {
		return false;
	}

	var stoptime = new Date();

	print("Ended at " + stoptime);

	var duration = stoptime.valueOf() - starttime.valueOf();

	print("Duration " + duration + " ms");
	
	print("Card id : " + chain.path);
	return true;
}



AccessController.prototype.check = function(card) {

	var grant = this.checkAccessWithSCHSM(card);
	if (grant) {
		this.accessTerminal.green();
	} else {
		this.accessTerminal.off();
		GPSystem.wait(200);
		this.accessTerminal.red();
		GPSystem.wait(200);
		this.accessTerminal.off();
		GPSystem.wait(200);
		this.accessTerminal.red();
		GPSystem.wait(200);
	}
}



AccessController.prototype.loop = function() {
	this.run = true;
	while (this.run) {
		this.accessTerminal.red();
		this.waitForCardInsertion();
		this.check(this.card);
		this.card.close();
		this.waitForCardRemoval();
	}
}



AccessController.prototype.stop = function() {
	this.run = false;
}



AccessController.test = function() {
	ac = new AccessController(_scsh3.reader);
	try	{
		Card.setCardEventListener(ac);
		ac.accessTerminal.red();
	}
	catch(e) {
//		ac.loop();
	}
}


AccessController.test();