import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root',
})
export class StorageService {
  constructor() {}

  setItem<T>(key: string, value: T): void {
    try {
      const jsonString: string = JSON.stringify(value);
      localStorage.setItem(key, jsonString);
    } catch (error) {
      console.error('Error saving to localStorage', error);
    }
  }

  getItem<T>(key: string): T | null {
    try {
      const jsonString: string = localStorage.getItem(key);
      return jsonString ? (JSON.parse(jsonString) as T) : null;
    } catch (error) {
      console.error('Error getting item from localStorage', error);
      return null;
    }
  }

  removeItem(key: string): void {
    localStorage.removeItem(key);
  }

  clear(): void {
    localStorage.clear();
  }
}
