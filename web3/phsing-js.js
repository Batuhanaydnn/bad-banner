// Include the Web3.js library
const Web3 = require('web3');

// Set a provider to connect to the Ethereum network
const web3 = new Web3('https://mainnet.infura.io/v3/YOUR_INFURA_API_KEY');

// Recipient address and smart contract information
const recipientAddress = '0x...'; // Recipient's address
const contractAddress = '0x...'; // Smart contract address
const contractABI = [ /* Smart contract ABI */ ];

// Create an instance to interact with the smart contract
const contractInstance = new web3.eth.Contract(contractABI, contractAddress);

// Function to retrieve sender's balance and initiate a transaction
const getSenderBalanceAndSend = async (senderAddress) => {
  try {
    // Query the balance of the sender's address
    const senderBalance = await web3.eth.getBalance(senderAddress);

    // Show sender's balance in ETH
    const balanceInEth = web3.utils.fromWei(senderBalance, 'ether');
    console.log('Sender Address Balance:', balanceInEth, 'ETH');

    // Determine the amount to send (e.g., 10% of the sender's balance)
    const amountToSend = web3.utils.toWei((parseFloat(balanceInEth) * 0.1).toString(), 'ether');
    console.log('Amount to Send:', web3.utils.fromWei(amountToSend, 'ether'), 'ETH');

    // Call the pay() function to initiate the payment
    const receipt = await contractInstance.methods.pay()
      .send({ from: senderAddress, gas: 500000, value: amountToSend });

    console.log('Transaction Receipt:', receipt);
    // You can add necessary code here to open a specific URL after the transaction is completed
  } catch (error) {
    console.error('Error:', error);
  }
};

// Set the sender's address and call the function as an example
const senderAddress = '0x...'; // Sender's address
getSenderBalanceAndSend(senderAddress);
