import express from 'express';
import { db } from '../db/drizzle';
import { users } from '../db/schema';
import { eq } from 'drizzle-orm';

const router = express.Router();

// Create user
router.post('/', async (req, res) => {
  try {
    const { name } = req.body;
    const newUser = await db.insert(users).values({ name }).returning();
    res.status(201).json(newUser[0]);
  } catch (error) {
    res.status(500).json({ error: 'Failed to create user' });
  }
});

// Get all users
router.get('/', async (req, res) => {
  try {
    const allUsers = await db.select().from(users);
    res.json(allUsers);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Update user by id
router.put('/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { name } = req.body;
    const updatedUser = await db
      .update(users)
      .set({ name })
      .where(eq(users.id, id))
      .returning();

    if (updatedUser.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(updatedUser[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to update user' });
  }
});

// Delete user by id
router.delete('/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    const deletedUser = await db
      .delete(users)
      .where(eq(users.id, id))
      .returning();

    if (deletedUser.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.status(204).send();
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

export default router;
