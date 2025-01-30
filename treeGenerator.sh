#!/bin/bash

#The file where the tree will be inserted
FILE="Directory_Tree.md"

#Create the starting section
echo "# Directory Tree" > $FILE
echo '```' >> $FILE

#Generate the tree
tree -L 4 >> $FILE

#Close the block
echo '```' >> $FILE
