# Follow The White Rabbit - Datamining

For this challenge we are provided with a Unity game `FollowWhiteRabbit`. We can easily inspect and alter the game's logic using `dnSpy` on the `Assembly-CSharp.dll`.

For the second part of this challenge, we have to find some unreleased content contained in the game. This content is probably contained in its own Scene, separated from the current content.

We'll be patching `PlayerController.CheckFallDeath` as in the first part. Let's list all available scenes:

```csharp
private void CheckFallDeath()
{
    for (int i = 0; i < SceneManager.sceneCount; i++) {
        Scene s = SceneManager.GetSceneAt(i);
        File.AppendAllText("output.txt", s.name + " - " + s.path);
    }
}
```

This only finds the Scene `FlagLand`, so apparently is only lists loaded scenes. We have to find the hidden Scene in a different way.

`grep`ing all of the game files for `FlagLand`, we find the paths of additional Scenes in `FollowWhiteRabbit_Data/globalgamemanagers`: `Assets/Scenes/UI/UI_MENU.unity`, `Assets/Scenes/UI/UI_LOADING.unity`, `Assets/Scenes/FlagLand.unity`, `Assets/Scenes/UI/UI_GAMEOVER.unity`, `Assets/Scenes/UI/UI_FPS.unity`, `Assets/Scenes/FlagLand_Update.unity`. `FlagLand_Update` sounds exactly like the Scene we are looking for!

When we load the updated scene by introducing a new shortcut, the game just hangs:

```csharp
private void CheckFallDeath()
{
    if (Input.GetKey(KeyCode.L))
    {
        SceneManager.LoadScene("FlagLand_Update");
    }
}
```

Maybe we have to load the new Scene in addition to the old Scene:

```csharp
private void CheckFallDeath()
{
    if (Input.GetKey(KeyCode.L))
    {
        SceneManager.LoadSceneAsync("FlagLand_Update", LoadSceneMode.Additive);
    }
}
```

Now the game no longer hangs, and a new house appears next to the prison! The house it too high up for us to reach it, so let's add a teleport binding to our patch:

```csharp
private void CheckFallDeath()
{
    if (Input.GetKey(KeyCode.P))
    {
        this.teleportTo(base.transform.position + base.transform.forward * 2f);
    }
    if (Input.GetKey(KeyCode.O))
    {
        this.teleportTo(base.transform.position + base.transform.up * 10f);
    }
    if (Input.GetKey(KeyCode.L))
    {
        SceneManager.LoadSceneAsync("FlagLand_Update", LoadSceneMode.Additive);
    }
}
```

With our new teleport abilities, we can easily get into the house, where we see the flag displayed on a monitor: `CSCG{03ASY_teleport_and_datamining_scenes}`
