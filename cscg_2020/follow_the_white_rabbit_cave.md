# Follow The White Rabbit - Cave

For this challenge we are provided with a Unity game `FollowWhiteRabbit`. We can easily inspect and alter the game's logic using `dnSpy` on the `Assembly-CSharp.dll`.

For the first part of this challenge, we have to follow the white rabbit into the cave. However, we always die when hitting the ground after jumping in the cave. This can be prevented by patching the game logic and removing the code responsible for death through falling in `PlayerController.CheckFallDeath`:

```diff
 // PlayerController
 private void CheckFallDeath()
 {
-    if (this.m_IsGrounded && this.m_VerticalSpeed < -(this.maxGravity - 0.1f))
-    {
-        this.Die();
-    }
 }
```

Now we can jump into the cave without dying, and follow the rabbit to the flag: `CSCG{data_mining_teleport_or_gravity_patch?}`
