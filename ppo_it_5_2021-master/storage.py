from random import randint, seed
import json

MIN_SIZE = 3
MAX_SIZE = 3
MIN_MERGED_CELLS = 2

QUAD_CELLS = 4
DOUBLE_CELLS = 2


class Storage:
    def __init__(self):
        self.x = 0
        self.y = 0
        self.z = 0
        self.mergedCells = []
        self.busyCells = []
        self.storageStructure = {
            'size': {},
            'merged': []
        }

    def setStorageSizes(self, x, y, z):
        if x > 0 and y > 0 and z > 0:
            self.x = int(x)
            self.y = int(y)
            self.z = int(z)
            self.storageStructure['size']['size_x'] = self.x
            self.storageStructure['size']['size_y'] = self.y
            self.storageStructure['size']['size_z'] = self.z

    def changeCellName(self, x, y):
        return chr(ord(str(x)) + 16) + str(y)

    def setStorageMergedCells(self, cellsList):
        addedList = []
        for i in range(0, len(cellsList) - 1, 2):
            self.mergedCells.append([cellsList[i], cellsList[i + 1]])
            addedList.append(self.changeCellName(cellsList[i], cellsList[i+1]))
        self.storageStructure['merged'].append(sorted(addedList))

    def generateRandomMergedCells(self, typeMergCells):
        localX = max(self.x, self.z)
        x1 = randint(1, localX)
        y1 = randint(1, self.y)
        x2 = x1
        y2 = y1 + 1 if y1 < self.y else y1 - 1
        iter = 0
        while ([x1, y1] in self.mergedCells or [x2, y2] in self.mergedCells):
            x1 = randint(1, localX)
            y1 = randint(1, self.y)
            x2 = x1
            y2 = y1 + 1 if y1 < self.y else y1 - 1
            iter += 1
            if iter == 200:
                return
        if typeMergCells == DOUBLE_CELLS:
            self.setStorageMergedCells([x1, y1, x2, y2])
            return
        if typeMergCells == QUAD_CELLS:
            x3 = x1 + 1 if x1 < localX else x1 - 1
            x4 = x3
            y3 = y1
            y4 = y2
            if [x3, y3] in self.mergedCells or [x4, y4] in self.mergedCells:
                return False
            else:
                self.setStorageMergedCells([x1, y1, x2, y2, x3, y3, x4, y4])
                return True

    def generateStorage(self):
        typeOfStorage = 1
        if typeOfStorage == 1:
            self.setStorageSizes(randint(MIN_SIZE, MAX_SIZE),
                                 randint(MIN_SIZE, MAX_SIZE), 1)
        else:
            self.setStorageSizes(1, randint(MIN_SIZE, MAX_SIZE),
                                 randint(MIN_SIZE, MAX_SIZE))
        localX = max(self.x, self.z)
        maxQuontatyMerged = localX * self.y // 3
        quontatyMerged = randint(MIN_MERGED_CELLS, maxQuontatyMerged)
        quontSquadCells = quontatyMerged // 3 if quontatyMerged // 3 > 1 else 1
        for _ in range(quontSquadCells):
            self.generateRandomMergedCells(QUAD_CELLS)
        for _ in range(quontatyMerged - quontSquadCells):
            self.generateRandomMergedCells(DOUBLE_CELLS)
        self.storageStructure['merged'].sort()

    def putInStorage(self, id, destination):
        returnCode = True
        if destination in self.storageStructure['merged']:
            for i in destination:
                if i in self.busyCells:
                    returnCode = False
                    break
            if returnCode is True:
                for i in destination:
                    self.busyCells.append(i)
        elif len(destination) == 1:
            strDest = destination[0]
            x = int(chr(ord(strDest[0]) - 16))  # from symbol to int
            y = int(strDest[1])
            localX = max(self.x, self.z)
            if (x <= localX and y <= self.y and
                    strDest not in self.busyCells):
                self.busyCells.append(strDest)
            else:
                returnCode = False
        else:
            returnCode = False
        return returnCode

    def checkCellExistence(self, cellName):
        localX = max(self.x, self.z)
        if len(cellName) > 2 or cellName[0] > 'I':
            return False
        x = int(chr(ord(cellName[0]) - 16))
        y = int(cellName[1])
        print(x)
        print(y)
        if (x <= localX and y <= self.y):
            return True
        else:
            return False

    def getFromStorage(self, destination):
        returnCode = 0
        for i in destination:
            cellInStorageFlag = True if self.checkCellExistence(i) else False
            if cellInStorageFlag is True:
                if i in self.busyCells:
                    self.busyCells.remove(i)
                else:
                    returnCode = -1
            else:
                returnCode = -2
        return returnCode


if __name__ == '__main__':
    st = Storage()
    st.generateStorage()
    print(st.storageStructure)
