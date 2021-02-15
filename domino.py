import random


class Domino:
    '''represents a single domino
    attribute:
      pips: a tuple representing the two pips'''

    def __init__(self,a,b):
        '''Domino(a,b) -> Domino
        creates the domino a-b'''
        self.pips = ((a,b))

    def __str__(self):
        '''str(Domino) -> str'''
        return str(self.pips[0])+'-'+str(self.pips[1])

    def reverse_str(self):
        '''Domino.reverse_str() -> str
        string with pips reversed'''
        return str(self.pips[1])+'-'+str(self.pips[0])

    def get_pips(self):
        '''Domino.get_pips() -> tuple
        returns the pips of the domino'''
        return self.pips

    def reverse(self):
        '''Domino.reverse()
        reverses the pips'''
        (a,b) = self.pips
        self.pips = (b,a)

    def is_match(self,pip):
        '''Domino.is_match(pip) -> int
        checks if the domino matches the given pip
        returns the index (0 or 1) of the half that matches
        returns -1 if not a match'''
        if self.pips[0]==pip:
            return 0
        elif self.pips[1]==pip:
            return 1
        else:
            return -1

    def is_double(self):
        return self.pips[0] == self.pips[1]

    def pip_sum(self):
        return self.pips[0] + self.pips[1]

    def __eq__(self, domino):
        return (self.pips[0] == domino.get_pips()[0] and self.pips[1] == domino.get_pips()[1]) or (self.pips[0] == domino.get_pips()[1] and self.pips[1] == domino.get_pips()[0])


class DominoSet():
    '''represents a full set of dominos'''

    def __init__(self):
        '''DominoSet() -> DominoSet'''
        self.dominoes = []
        for a in range(7):
            for b in range(a,7):
                self.dominoes.append(Domino(a,b))
        random.shuffle(self.dominoes)

    # __str__ doesn't seem necessary -- we never need a
    #  string rep for our DominoSet since it's created
    #  and then immediately consumed

    def deal(self):
        '''DominoSet.deal() -> list
        returns a list of 7 dominoes'''
        #return [self.dominoes.pop() for i in range(7)]
        return [self.dominoes.pop() for i in range(5)]

    def getStack(self):
        '''DominoSet.getStack() -> list
        returns a list of the dominoe list'''
        return self.dominoes

    def isEmpty(self):
        ''' DominoSet.isEmpty() -> boolean '''
        return not self.dominoes

    def pop(self):
        ''' DominoSet.pop() -> Domino '''
        return self.dominoes.pop()


class Chain:
    '''represents a domino chain
    attributes:
      chain: a list of dominoes'''

    def __init__(self):
        '''Chain() -> Chain
        start a new domino chain with the 6-6 domino'''
        #self.chain = [Domino(6,6)]
        self.chain = []

    def __str__(self):
        '''str(Chain) -> str'''
        return ','.join([str(d) for d in self.chain])

    def left_end(self):
        '''Chain.left_end() -> int
        returns the number on the left end of the chain'''
        # return the first number on the first domino
        return self.chain[0].get_pips()[0]

    def right_end(self):
        '''Chain.right_end() -> int
        returns the number on the right end of the chain'''
        # return the second number on the last domino
        return self.chain[-1].get_pips()[1]

    def is_playable(self,domino):
        '''Chain.is_playable(Domino) -> boolean
        returns True if the domino can be played on either end
          of the chain, False if not'''
        # must check if it is a match at either end
        if domino.get_pips()[0] < 0 or domino.get_pips()[0] > 6 or domino.get_pips()[1] < 0 or domino.get_pips()[1] > 6:
            return False

        if self.contains(domino):
            return False

        return domino.is_match(self.left_end())>=0 or \
               domino.is_match(self.right_end())>=0

    def contains(self, domino):
        for d in self.chain:
            if domino == d:
                return True
        return False

    def add(self,domino,rightOnly=False):
        '''Chain.add(domino)
        adds a domino to the chain
        does nothing if the domino cannot be added
        if rightOnly is True, only plays on the right side'''
        # check both pips of the domino at both ends
        #  of the chain -- reverse if necessary before adding
        if not rightOnly and domino.is_match(self.left_end()) == 0:
            # left pip at left end
            domino.reverse()
            self.chain.insert(0,domino)
        elif not rightOnly and domino.is_match(self.left_end()) == 1:
            # right pip at left end
            self.chain.insert(0,domino)
        elif domino.is_match(self.right_end()) == 0:
            # left pip at right end
            self.chain.append(domino)
        elif domino.is_match(self.right_end()) == 1:
            # right pip at right end
            domino.reverse()
            self.chain.append(domino)

    def start(self, domino):
        ''' adds the first domino to the chain '''
        self.chain = [domino]

    def getList(self):
        lst = []
        for d in self.chain:
            lst.append(d.get_pips())
        return lst

    def isEmpty(self):
        return not self.chain


class Player:
    '''represents a dominoes player
    attributes:
      isHuman: True if human, False if computer
      hand: a Hand'''

    def __init__(self,i,isHuman,dominoes):
        '''Player(isHuman,dominoes) -> Player
        creates a new player with a 7-domino hand taken from dominoes
        isHuman is True for a human player, False for a computer player'''
        self.isHuman = isHuman
        self.hand = dominoes.deal()
        self.table = dominoes
        self.id = i

    def __str__(self):
        '''str(Player) -> str'''
        if self.isHuman:
            return 'You have '+str(len(self.hand))+' dominoes'
        else:
            return 'A computer player has '+str(len(self.hand))+' dominoes'

    def is_human(self):
        '''Player.is_human() -> boolean
        returns True for a human player, False for a computer player'''
        return self.isHuman

    def goes_first(self):
        '''Player.goes_first() -> boolean
        makes first move and returns True if player has 6-6
        returns False otherwise'''
        for domino in self.hand:
            if domino.get_pips()[0] == 6 and domino.get_pips()[1] == 6:
                self.hand.remove(domino)
                return True
        return False

    def highest_double(self):
        hightDomino = None 
        for domino in self.hand:
            if domino.is_double():
                if hightDomino != None:
                    if domino.get_pips()[0] > hightDomino.get_pips()[0]:
                        hightDomino = domino
                else:
                    hightDomino = domino
        return hightDomino

    def highest_pips(self):
        hightDomino = None 
        for domino in self.hand:
            if hightDomino != None:
                if domino.pip_sum() > hightDomino.pip_sum():
                    hightDomino = domino
            else:
                hightDomino = domino
        return hightDomino

    def has_won(self):
        '''Player.has_won() -> boolean
        returns True if the player has won, False otherwise'''
        # player wins if his hand is empty
        return len(self.hand) == 0

    def take_turn(self,chain):
        '''Player.take_turn(chain) -> boolean
        takes the player's turn in the game
        chain is the current chain
        returns True if the player passes, False otherwise'''
        if self.isHuman:  # human player's turn
            # print the chain and the player's hand
            print("It's your turn.")
            print("The current chain:")
            print(chain)
            print("Your hand:")
            print('\n'.join([str(self.hand.index(d))+': '+str(d) for d in self.hand]))

            while True:  # get a choice of a domino to play, or pass
                choice = input("Which do you want to play? Enter p to pass. ")
                if choice.lower() == 'p':  # pass
                    break
                if choice.lower() == 's':  # get domino from the stack
                    if (self.table.isEmpty()):
                        print("The table stack is empty!")
                    else:
                        domino = self.table.pop()
                        self.hand.append(domino)
                        print("You poped "+ str(domino) +" from the table stack.")
                    print("The current chain:")
                    print(chain)
                    print("Your hand:")
                    print('\n'.join([str(self.hand.index(d))+': '+str(d) for d in self.hand]))
                if choice.isdigit():  # wants to play
                    # validate the choice
                    if (int(choice) < 0 or int(choice) >= len(self.hand)):
                        print("Invalid domino number!")
                    elif not chain.is_playable(self.hand[int(choice)]):
                        print("That domino is not playable!")
                    else:
                        break

            if choice.isdigit():  # play
                choice = int(choice)
                domino = self.hand.pop(choice) # remove domino from hand
                rightOnly = False  # by default play on either side
                # if can play on either side, ask which side
                if domino.is_match(chain.left_end()) >= 0 and \
                   domino.is_match(chain.right_end()) >= 0:
                    print("That domino matches both sides of the chain.")
                    response = 'x'
                    while response.lower() not in 'lr':
                        response = input("Which side do you want to play it on? (Type l or r) ")
                    if response.lower() == 'r':
                        rightOnly = True
                chain.add(domino,rightOnly) # add domino to chain
                return False
            else:
                return True

        else:  # computer player
            # get list of dominos that the computer can play
            print("The current chain:")
            print(chain)

            while(True):
                playlist = [d for d in self.hand if chain.is_playable(d)]

                if len(playlist) > 0:  # can play
                    # pick a playable domino at random and play it
                    domino = playlist[random.randrange(len(playlist))]
                    self.hand.remove(domino)  # remove domino from hand
                    chain.add(domino)  # add domino to chain
                    print("Computer player " + str(self.id) + " plays "+str(domino)+", has "+\
                        str(len(self.hand))+" dominoes remaining.")
                    return False

                else: # computer can't play
                    # pick a domino from the table stack
                    # if the stack is empty, the ai player passes
                    if (self.table.isEmpty()):
                        print("Computer player " + str(self.id) + " passes"+", has "+\
                        str(len(self.hand))+" dominoes remaining.")
                        return True
                    else:
                        domino = self.table.pop()
                        self.hand.append(domino)
                        print("Computer player " + str(self.id) + " poped "+ str(domino) +
                        " from the table stack.")
                        


def play_solo(n) :
    '''play_solo() -> number
    plays dominoes with 1 human and 3 computer players
    returns player number of winner (human = 0)'''
    # create new set of dominoes and initialize the chain
    dominoes = DominoSet()
    chain = Chain()

    # create human player
    playerList = [Player(0,True,dominoes)]
    # create n-1 computer players
    for i in range(n-1):
        playerList.append(Player(i+1,False,dominoes))
    

    # figure out which player goes first
    # first move is automatic, so set currentPlayerNum to the next player
    '''
    for i in range(n):
        if playerList[i].goes_first():
            if playerList[i].is_human():
                print("You went first by placing 6-6.")
            else:
                print("A computer player went first by placing 6-6.")
            currentPlayerNum = (i+1)%n
    '''
    hightDomino = None
    hightPlayer = None

    for i in range(n):
        #primeiro critério é verificar quem tem o double mais alto
        domino = playerList[i].highest_double()
        #print(domino)
        if domino != None:
            if hightDomino != None:
                if domino.get_pips()[0] > hightDomino.get_pips()[0]:
                    hightDomino = domino
                    hightPlayer = i
            else:
                hightDomino = domino
                hightPlayer = i
        #se ninguém tiver um double, começa quem tiver a peça com mais pips
    if hightPlayer == None:
        for i in range(n):
            domino = playerList[i].highest_pips()
            if hightDomino != None:
                if domino.pip_sum() > hightDomino.pip_sum():
                    hightDomino = domino
                    hightPlayer = i
            else:
                hightDomino = domino
                hightPlayer = i
                
    chain.start(hightDomino)
    playerList[hightPlayer].hand.remove(hightDomino)
    if (playerList[hightPlayer].is_human()):
        print("You went first by placing "+str(hightDomino)+".")
    else:
        print("A computer player went first by placing "+str(hightDomino)+".")
    currentPlayerNum = (hightPlayer+1)%n
    print("Stack: "+','.join([str(d) for d in dominoes.getStack()]))


    passCount = 0  # to keep track if there are n passes in a row
    while True:  # play the game
        player = playerList[currentPlayerNum] # the current player
        passed = player.take_turn(chain)  # take a turn
        if passed:
            passCount += 1  # increase the pass count
        else:
            passCount = 0  # reset the pass count
        if player.has_won() or passCount == n:  # game is over
            # print winning message
            if player.is_human():
                print("You won!")
            else:
                print("Sorry, a computer player won.")
            return currentPlayerNum  #  end the game
        # go to the next player
        currentPlayerNum = (currentPlayerNum + 1) % n

def play_ai(n) :
    '''play_solo() -> number
    plays dominoes with 1 human and 3 computer players
    returns player number of winner (human = 0)'''
    # create new set of dominoes and initialize the chain
    dominoes = DominoSet()
    chain = Chain()

    playerList = []
    # create n computer players
    for i in range(n):
        playerList.append(Player(i,False,dominoes))
    

    # figure out which player goes first
    # first move is automatic, so set currentPlayerNum to the next player
    hightDomino = None
    hightPlayer = None

    for i in range(n):
        #primeiro critério é verificar quem tem o double mais alto
        domino = playerList[i].highest_double()
        #print(domino)
        if domino != None:
            if hightDomino != None:
                if domino.get_pips()[0] > hightDomino.get_pips()[0]:
                    hightDomino = domino
                    hightPlayer = i
            else:
                hightDomino = domino
                hightPlayer = i
        #se ninguém tiver um double, começa quem tiver a peça com mais pips
    if hightPlayer == None:
        for i in range(n):
            domino = playerList[i].highest_pips()
            if hightDomino != None:
                if domino.pip_sum() > hightDomino.pip_sum():
                    hightDomino = domino
                    hightPlayer = i
            else:
                hightDomino = domino
                hightPlayer = i
                
    chain.start(hightDomino)
    playerList[hightPlayer].hand.remove(hightDomino)
    if (playerList[hightPlayer].is_human()):
        print("You went first by placing "+str(hightDomino)+".")
    else:
        print("A computer player went first by placing "+str(hightDomino)+".")
    currentPlayerNum = (hightPlayer+1)%n
    #print("Stack: "+','.join([str(d) for d in dominoes.getStack()]))


    passCount = 0  # to keep track if there are n passes in a row
    while True:  # play the game
        player = playerList[currentPlayerNum] # the current player
        passed = player.take_turn(chain)  # take a turn
        if passed:
            passCount += 1  # increase the pass count
        else:
            passCount = 0  # reset the pass count
        if player.has_won() or passCount == n:  # game is over
            # print winning message
            if player.is_human():
                print("You won!")
            else:
                print("Computer player " + str(currentPlayerNum) + " won.")
            return currentPlayerNum  #  end the game
        # go to the next player
        currentPlayerNum = (currentPlayerNum + 1) % n

# play the game
#play_solo(2)
#play_ai(2)
