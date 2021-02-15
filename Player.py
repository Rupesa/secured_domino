class Player:
	def __init__(self, pseudonym, socket, pubKey, pubHash, key, points, cert):
		
		self.pseudonym = pseudonym
		self.socket = socket
		self.pubKey = pubKey
		self.pubHash = pubHash
		self.serverKey  = key
		self.points = points
		self.cert = cert

	def pseudonym(self):
		return self.pseudonym

	def socket(self):
		return self.socket

	def pubKey(self):
		return self.pubKey

	def pubHash(self):
		return self.pubHash

	def set_points(self):
		self.points = self.points + 10
		return

	def cc_pub_key(self):
		return self.cc_pub_key

	def show_points(self):
		return self.points

	
