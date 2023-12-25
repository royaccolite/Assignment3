package com.bezkoder.springjwt.dto;

public class WalletBalanceDto {

    private int balance;

    public WalletBalanceDto(int balance) {
        this.balance = balance;
    }

    public int getBalance() {
        return balance;
    }

    // Add setters if needed

    @Override
    public String toString() {
        return "WalletBalanceDto{" +
                "balance=" + balance +
                '}';
    }
}
